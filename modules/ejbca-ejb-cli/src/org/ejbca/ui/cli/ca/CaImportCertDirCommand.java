/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.ca;

import java.io.File;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.DnComponents;

/**
 * Imports certificate files to the database for a given CA
 *
 * @version $Id$
 */
public class CaImportCertDirCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaImportCertDirCommand.class);

    public static final String DATE_FORMAT = "yyyy.MM.dd-HH:mm";
    public static final String DATE_FORMAT_WINSAFE = "yyyy.MM.dd-HH.mm"; // The colon character (:) will cause issued within Windows filenames, so use a period instead. 

    private static final String USERNAME_FILTER_KEY = "--filter";
    private static final String CA_NAME_KEY = "--caname";
    private static final String ACTIVE_KEY = "-a";
    private static final String RESUME_ON_ERROR_KEY = "-resumeonerror";
    private static final String DIRECTORY_KEY = "--dir";
    private static final String EE_PROFILE_KEY = "--eeprofile";
    private static final String CERT_PROFILE_KEY = "--certprofile";
    private static final String REVOCATION_REASON = "--revocation-reason";
    private static final String REVOCATION_TIME = "--revocation-time";
    private static final String THREAD_COUNT = "--threads";
    private static final String CACERT = "--cacert";
    private static final String REVOKEDETAILS = "--revoke-details-in-filename";

    private static final String ACTIVE = "ACTIVE";
    private static final String REVOKED = "REVOKED";

    {
        registerParameter(new Parameter(USERNAME_FILTER_KEY, "Filter", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "\"DN\" means use certificate's SubjectDN as username, \"CN\" means use certificate subject's common name as username and \"FILE\" means user the file's name as username"));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the issuing CA."));
        registerParameter(new Parameter(ACTIVE_KEY, ACTIVE + "|" + REVOKED, MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Set the status of the imported end entity."));
        registerParameter(new Parameter(DIRECTORY_KEY, "Certificate Directory", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Directory of PEM certificates, which must be PEM encoded"));
        registerParameter(new Parameter(EE_PROFILE_KEY, "Profile Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "End Entity Profile to create end entity with."));
        registerParameter(new Parameter(CERT_PROFILE_KEY, "Profile Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Certificate Profile to create end entity with."));
        registerParameter(Parameter.createFlag(RESUME_ON_ERROR_KEY,
                "Set if the import should resume in case of errors, or stop on first one. Default is stop"));
        registerParameter(new Parameter(REVOCATION_REASON, "Reason", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Revocation reason, if the certificates are to be imported as revoked. Will be set to " + RevocationReasons.UNSPECIFIED.getStringValue() + " if this option is not set."));
        registerParameter(new Parameter(REVOCATION_TIME, DATE_FORMAT, MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Revocation time, if the certificates are to be imported as revoked. Will be set to the current time if this option is not set. Format is "
                        + DATE_FORMAT + ", i.e. 2015.05.04-10:15"));
        registerParameter(new Parameter(THREAD_COUNT, "Thread count", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Number of threads used during the import. Default is 1 thread."));
        registerParameter(new Parameter(CACERT, "CA Certificate File", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Specify an alternate CA certificate file (in PEM). Use this option when importing certificates that were issued by the previous CA certificate. Please note that the supplied certificate is not verified."));
        registerParameter(new Parameter(REVOKEDETAILS, "Revocation Details", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Revocation details are to be derived from the filename of the certificate. The filename must end with '!<REASON>!<INVALIDITY_TIME>'. The REASON can be the value or label as described in RFC5280 section 5.3.1. "
                + "INVALIDITY_TIME is formatted as '"+DATE_FORMAT_WINSAFE+"' and assumed to be the local timezone. Note: Filename extensions (ie., '.crt. or '.pem') are not supported. Please also note that any file without "
                + "revocation details will not be imported."));
   }

    @Override
    public String getMainCommand() {
        return "importcertdir";
    }

    @Override
    public CommandResult execute(final ParameterContainer parameters) {
        log.trace(">execute()");

        CryptoProviderTools.installBCProviderIfNotAvailable();

        // Parse arguments into more coder friendly variable names and validate switches
        final String usernameFilter = parameters.get(USERNAME_FILTER_KEY);
        final String caName = parameters.get(CA_NAME_KEY);
        final String active = parameters.get(ACTIVE_KEY);
        final String certificateDir = parameters.get(DIRECTORY_KEY);
        final String eeProfile = parameters.get(EE_PROFILE_KEY);
        final String certificateProfile = parameters.get(CERT_PROFILE_KEY);
        final String revocationReasonString = parameters.get(REVOCATION_REASON);
        final String revocationTimeString = parameters.get(REVOCATION_TIME);
        final int threadCount = parameters.get(THREAD_COUNT) == null ? 1 : Integer.valueOf(StringUtils.strip(parameters.get(THREAD_COUNT)));
        final String caCertFile = parameters.get(CACERT);

        if (threadCount > 1 && !usernameFilter.equalsIgnoreCase("FILE")) {
            log.error("If more than one thread is being used, filename must be used as filter (use the argument --filter FILE).");
            return CommandResult.CLI_FAILURE;
        }

        // Specifies whether the import should resume in case of errors, or stop
        // on first one. Default is stop.
        final boolean resumeOnError = parameters.containsKey(RESUME_ON_ERROR_KEY);

        // Thread pool for running multiple import operations simultaneously
        final ExecutorService executorService = Executors.newFixedThreadPool(threadCount);

        try {
            final int status;
            RevocationReasons revocationReason = null;
            Date revocationTime = null;
            if ("ACTIVE".equalsIgnoreCase(active)) {
                status = CertificateConstants.CERT_ACTIVE;
                if(revocationReasonString != null) {
                    log.warn("Revocation reason has been set in spite of certificates being imported as active. Ignoring.");
                }
                if(revocationTimeString != null) {
                    log.warn("Revocation time has been set in spite of certificates being imported as active. Ignoring.");
                }
            } else if ("REVOKED".equalsIgnoreCase(active)) {
                status = CertificateConstants.CERT_REVOKED;
                if(revocationReasonString != null) {
                    revocationReason = RevocationReasons.getFromCliValue(revocationReasonString.toUpperCase());
                    if(revocationReason == null) {
                        log.error("ERROR: " + revocationReasonString + " is not a valid revocation reason.");
                        return CommandResult.CLI_FAILURE;
                    }
                } else {
                    revocationReason = RevocationReasons.UNSPECIFIED;
                }
                if (revocationTimeString != null) {
                    try {
                        revocationTime = new SimpleDateFormat(DATE_FORMAT).parse(revocationTimeString);
                    } catch (ParseException e) {
                        log.error("ERROR: " + revocationTimeString + " was not a valid revocation time.");
                        return CommandResult.CLI_FAILURE;
                    }
                } else {
                    revocationTime = new Date();
                }

            } else {
                log.error("Invalid certificate status.");
                return CommandResult.CLI_FAILURE;
            }
            if (!usernameFilter.equalsIgnoreCase("DN") && !usernameFilter.equalsIgnoreCase("CN") && !usernameFilter.equalsIgnoreCase("FILE")) {
                log.error(usernameFilter
                        + "is not a valid option. Currently only \"DN\", \"CN\" and \"FILE\" username-source are implemented");
                return CommandResult.CLI_FAILURE;
            }

            // Fetch CA info
            final CAInfo caInfo = getCAInfo(getAuthenticationToken(), caName);
            
            X509Certificate cacert = (X509Certificate) caInfo.getCertificateChain().iterator().next();
            // Override the CA certificate if provided in the options
            if ( caCertFile != null) {
                final File fileCaCertFile = new File(caCertFile);
                if (!fileCaCertFile.isFile()) {
                    log.error("CA Certificate file '" + caCertFile + "' is not found. Please check the supplied parameters.");
                    return CommandResult.CLI_FAILURE;
                } else {
                    List<X509Certificate> certsInFile = CertTools.getCertsFromPEM( fileCaCertFile.getCanonicalPath(), X509Certificate.class);
                    if ( (certsInFile == null) || (certsInFile.size()<1)) {
                        log.error("CA Certificate file '" + caCertFile + "' could not be processed. Please check the file.");
                        return CommandResult.CLI_FAILURE;
                    }
                    if ( certsInFile.size()>1) {
                        log.warn("CA Certificate file '" + caCertFile + "' contains more than one certificate. Assuming the first certificate.");
                    }
                   // Assume the first certificate, in case more than one provided.
                    cacert = certsInFile.get(0);
                    log.warn("The certificate for the CA has been overidden. This certificate has not been verified. Use at your own risk. Certificate details: "+cacert.toString());
                }
            }
            
            final String issuer = DnComponents.stringToBCDNString(cacert.getSubjectDN().toString());
            log.info("CA: " + issuer);
            // Fetch End Entity Profile info
            log.debug("Searching for End Entity Profile " + eeProfile);
            final int endEntityProfileId = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                    .getEndEntityProfileId(eeProfile);
            // Fetch Certificate Profile info
            log.debug("Searching for Certificate Profile " + certificateProfile);
            final int certificateProfileId = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(
                    certificateProfile);
            if (certificateProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                log.error("ERROR: Certificate Profile " + certificateProfile + " does not exist.");
                throw new Exception("Certificate Profile '" + certificateProfile + "' does not exist.");
            }
            // Get all files in the directory to import from and try to read and import each as a certificate
            final File dir = new File(certificateDir);
            if (!dir.isDirectory()) {
                log.error("'" + certificateDir + "' is not a directory.");
                return CommandResult.CLI_FAILURE;
            }
            final File files[] = dir.listFiles();
            if (files == null || files.length < 1) {
                log.error("No files in directory '" + dir.getCanonicalPath() + "'. Nothing to do.");
                return CommandResult.CLI_FAILURE;
            }

            final Queue<Future<CertificateImporter.Result>> futures = new LinkedList<>();
            final List<CertificateImporter.Result> results = new LinkedList<>();
            int redundant = 0;
            int caMismatch = 0;
            int readError = 0;
            int constraintViolation = 0;
            int generalImportError = 0;
            int importOk = 0;

            final long startTime = System.currentTimeMillis();


            for (final File file : files) {
                
                // Check if revocation details are to be derived from the filename. Only do this if status is REVOKED
                if ( (status == CertificateConstants.CERT_REVOKED) &&  parameters.containsKey(REVOKEDETAILS)) {
                    // Find the revocation details from the filename. The details are separated with an exclamation (!) character.
                    final String[] sa = file.getName().split("!");
                    if (sa.length <3) {
                        log.error("ERROR: The revocation details are not found in filename '"+file.getName()+"'. Ignoring this file.");
                        continue;
                   } else {
                        // Process the REASON from 2nd last string in array
                        String sRevCode = sa[ sa.length-2 ].toUpperCase();
                        // Check if using a code value
                        try {
                            final int iRevCode = Integer.parseInt(sRevCode);
                            revocationReason = RevocationReasons.getFromDatabaseValue(iRevCode);
                            if(revocationReason == null) {
                                log.error("ERROR: '" + iRevCode + "' is not a valid revocation reason code. Ignoring this file '"+file.getName()+"'.");
                                continue;
                            }
                            
                        } catch (NumberFormatException e) {
                            // Not an integer, must be the full text
                            // Correct the string value to suit RevocationReason
                            if ( sRevCode.equals("KEYCOMPROMISE")) sRevCode = "KEY_COMPROMISE";
                            if ( sRevCode.equals("CACOMPROMISE")) sRevCode = "CA_COMPROMISE";
                            if ( sRevCode.equals("AFFILIATIONCHANGED")) sRevCode = "AFFILIATION_CHANGED";
                            if ( sRevCode.equals("CESSATIONOFOPERATION")) sRevCode = "CESSATION_OF_OPERATION";
                            if ( sRevCode.equals("CERTIFICATEHOLD")) sRevCode = "CERTIFICATE_HOLD";
                            if ( sRevCode.equals("PRIVILEGESWITHDRAWN")) sRevCode = "PRIVILEGES_WITHDRAWN";
                            if ( sRevCode.equals("CERTIFICATEHOLD")) sRevCode = "AA_COMPROMISE";
                                                             
                            revocationReason = RevocationReasons.getFromCliValue(sRevCode.toUpperCase());
                            if(revocationReason == null) {
                               log.error("ERROR: '" + sRevCode + "' is not a valid revocation reason. Ignoring this file '"+file.getName()+"'.");
                                continue;
                            }
                       }
                        
                        // Process the TIME from last string in array
                       final String sRevTime = sa[ sa.length-1 ];
                       try {
                            revocationTime = new SimpleDateFormat(DATE_FORMAT_WINSAFE).parse( sRevTime);
                        } catch (ParseException e) {
                            log.error("ERROR: '" + sRevTime + "' was not a valid revocation time. Use this time format '"+DATE_FORMAT_WINSAFE+"'. Ignoring this file '"+file.getName()+"'.");
                            continue;
                        }
                    }
                }                
                
                futures.add(executorService.submit(new CertificateImporter()
                        .setAuthenticationToken(getAuthenticationToken())
                        .setCaCertificate(cacert)
                        .setCaInfo(caInfo)
                        .setCertificateProfileId(certificateProfileId)
                        .setEndEntityProfileId(endEntityProfileId)
                        .setFileToImport(file)
                        .setIssuer(issuer)
                        .setResumeOnError(resumeOnError)
                        .setRevocationReason(revocationReason)
                        .setRevocationTime(revocationTime)
                        .setStatus(status)
                        .setUsernameFilter(usernameFilter)));
                // Process completed tasks
                while (futures.peek() != null && futures.peek().isDone()) {
                    results.add(futures.remove().get());
                }
            }

            for (final Future<CertificateImporter.Result> future : futures) {
                results.add(future.get());
            }

            for (final CertificateImporter.Result result : results) {
                if (result == CertificateImporter.Result.REDUNDANT) {
                    redundant++;
                } else if (result == CertificateImporter.Result.CA_MISMATCH) {
                    caMismatch++;
                } else if (result == CertificateImporter.Result.READ_ERROR) {
                    readError++;
                } else if (result == CertificateImporter.Result.CONSTRAINT_VIOLATION) {
                    constraintViolation++;
                } else if (result == CertificateImporter.Result.GENERAL_IMPORT_ERROR) {
                    generalImportError++;
                } else if (result == CertificateImporter.Result.IMPORT_OK) {
                    importOk++;
                }
            }

            final long stopTime = System.currentTimeMillis();
            final double seconds = (stopTime - startTime) / 1000;

            // Print resulting statistics
            log.info("\nImport summary:");
            log.info(importOk + " certificates were imported successfully.");
            log.info("Time: " + seconds + " seconds (" + (files.length / seconds) + " tps)");
            if (redundant > 0) {
                log.info(redundant + " certificates were already present in the database.");
            }
            if (caMismatch > 0) {
                log.info(caMismatch + " certificates were not issued by the specified CA.");
            }
            if (readError > 0) {
                log.info(readError + " certificates could not be read.");
            }
            if (constraintViolation > 0) {
                log.info(constraintViolation + " certificates violated the end entity constraints.");
            }
            if (generalImportError > 0) {
                log.info(generalImportError + " certificates were not imported due to other errors.");
            }
        } catch (Exception e) {
            log.error("ERROR: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } finally {
            executorService.shutdown();
            log.trace("<execute()");
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Imports a directory with PEM encoded certficate file(s) to the database, creating an End Entity (with random pwd and status 'generated') to map the each certificate to.";

    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\n");
        sb.append("The import will proceed as long as the only error encountered is a mismatch between the signer of end entity certificate "
                + "and the specified certification authority. If the -resumeonerror options is provided, the import will resume even in case of more "
                + "critical errors (such as violation of end entity constraints, malformed files etc). The offending files will be printed-out to the "
                + "standard output, and a summary will contain exact numbers on imported and failed certificates." + "\n\n");
        // List available CAs by name
        sb.append("Available CAs: " + getAvailableCasString() + "\n");
        sb.append("Available end entity profiles: " + getAvailableEepsString(AccessRulesConstants.CREATE_END_ENTITY) + "\n");
        sb.append("Available certificate profiles: " + getAvailableEndUserCpsString() + "\n");
        sb.append("Valid Revocation reasons: ");
        RevocationReasons[] values = RevocationReasons.values();
        for(int i = 0; i < values.length; ++i) {
            if(!values[i].equals(RevocationReasons.NOT_REVOKED)) {
                sb.append(values[i].getStringValue());
                if(i < values.length -1) {
                    sb.append(" | ");
                }
            }
        }

        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
