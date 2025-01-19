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
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * @version $Id$
 *
 */
public class CaImportCertDirCommandSystemTest {

    private static final String CA_NAME = "CaImportCertDirCommandSystemTest";
    private static final String CA_DN = "CN=" + CA_NAME;
    private static final String USERNAME = "CaImportCertDirCommandSystemTest";
    private static final String CERTIFICATE_DN = "CN=" + USERNAME + ",O=foo,C=SE";

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CaImportCertDirCommandSystemTest.class.getSimpleName());

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private CaImportCertDirCommand command = new CaImportCertDirCommand();
    private X509CA ca;
    private File certificateFile;
    private File tempDirectory;
    private BigInteger certificateSerialNumber;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        tempDirectory = FileTools.createTempDirectory();
        //Creates a CA with AlgorithmConstants.SIGALG_SHA256_WITH_RSA
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        caSession.addCA(authenticationToken, ca);
        certificateFile = File.createTempFile("test", null, tempDirectory);
        EndEntityInformation endEntityInformation = new EndEntityInformation(USERNAME, CERTIFICATE_DN, ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, null);
        endEntityInformation.setPassword("foo123");
        endEntityManagementSession.addUser(authenticationToken, endEntityInformation, false);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
        Certificate certificate = ((X509ResponseMessage) certificateCreateSession.createCertificate(authenticationToken, endEntityInformation, req,
                X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate();
        certificateSerialNumber = CertTools.getSerialNumber(certificate);
        FileOutputStream fileOutputStream = new FileOutputStream(certificateFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(certificate)));
        } finally {
            fileOutputStream.close();
        }
        List<Certificate> certs = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(USERNAME));
        if (certs.size() > 0) {
            for (Certificate cert : certs) {
                internalCertificateStoreSession.removeCertificate(cert);
            }
        }
        endEntityManagementSession.deleteUser(authenticationToken, USERNAME);
    }

    @After
    public void tearDown() throws Exception {
        if (ca != null) {
            CaTestUtils.removeCa(authenticationToken, ca.getCAInfo());
        }
        if (tempDirectory.exists()) {
            FileTools.delete(tempDirectory);
        }
        if (endEntityAccessSession.findUser(authenticationToken, USERNAME) != null) {
            endEntityManagementSession.deleteUser(authenticationToken, USERNAME);
        }
        List<Certificate> userCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(USERNAME));
        if (userCerts.size() > 0) {
            for (Certificate certificate : userCerts) {
                internalCertificateStoreSession.removeCertificate(certificate);
            }
        }
        if (endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN) != null) {
            endEntityManagementSession.deleteUser(authenticationToken, CERTIFICATE_DN);
        }
        List<Certificate> dnCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(CERTIFICATE_DN));
        if (dnCerts.size() > 0) {
            for (Certificate certificate : dnCerts) {
                internalCertificateStoreSession.removeCertificate(certificate);
            }
        }
    }

    @Test
    public void testCommand() throws AuthorizationDeniedException {
        String[] args = new String[] { "DN", CA_NAME, "ACTIVE", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
    }
    
    @Test
    public void testImportRevoked() throws AuthorizationDeniedException {
        String[] args = new String[] { "DN", CA_NAME, "REVOKED", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.UNSPECIFIED.getDatabaseValue(), certificateStatus.revocationReason);
    }
    
    @Test
    public void testImportRevokedWithReasonAndTime() throws AuthorizationDeniedException, ParseException {
        String[] args = new String[] { "DN", CA_NAME, "REVOKED", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER",
                "--revocation-reason", RevocationReasons.CACOMPROMISE.getStringValue(), "--revocation-time", "2015.05.04-10:15" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.CACOMPROMISE.getDatabaseValue(),
                certificateStatus.revocationReason);
        assertEquals("Certificate revocation date was incorrectly imported.", new SimpleDateFormat(CaImportCertDirCommand.DATE_FORMAT).parse("2015.05.04-10:15"),
                certificateStatus.revocationDate);
    }
    
    @Test
    public void testImportRevokedWithReasonAndTimeInFilennameReasonCode() throws AuthorizationDeniedException, ParseException {
        // Rename the certificate file
        File newFile = new File(tempDirectory, "test!cert!6!2022.07.08-15.49");
        certificateFile.renameTo(newFile);
        String[] args = new String[] { "DN", CA_NAME, "REVOKED", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER",
                "--revoke-details-in-filename" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.CERTIFICATEHOLD.getDatabaseValue(),
                certificateStatus.revocationReason);
        assertEquals("Certificate revocation date was incorrectly imported.", new SimpleDateFormat(CaImportCertDirCommand.DATE_FORMAT_WINSAFE).parse("2022.07.08-15.49"),
                certificateStatus.revocationDate);
    }

    @Test
    public void testImportRevokedWithReasonAndTimeInFilennameReasonText() throws AuthorizationDeniedException, ParseException {
        // Rename the certificate file
        File newFile = new File(tempDirectory, "!affiliationChanged!2023.08.21-05.26");
        certificateFile.renameTo(newFile);
        String[] args = new String[] { "DN", CA_NAME, "REVOKED", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER",
                "--revoke-details-in-filename" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.AFFILIATIONCHANGED.getDatabaseValue(),
                certificateStatus.revocationReason);
        assertEquals("Certificate revocation date was incorrectly imported.", new SimpleDateFormat(CaImportCertDirCommand.DATE_FORMAT_WINSAFE).parse("2023.08.21-05.26"),
                certificateStatus.revocationDate);
    }

    @Test
    public void testImportRevokedWithReasonAndTimeInFilennameReasonTextWithUnderscores() throws AuthorizationDeniedException, ParseException {
        // Rename the certificate file
        File newFile = new File(tempDirectory, "test!CESSATION_OF_OPERATION!2021.02.28-0.01");
        certificateFile.renameTo(newFile);
        String[] args = new String[] { "DN", CA_NAME, "REVOKED", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER",
                "--revoke-details-in-filename" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.CESSATIONOFOPERATION.getDatabaseValue(),
                certificateStatus.revocationReason);
        assertEquals("Certificate revocation date was incorrectly imported.", new SimpleDateFormat(CaImportCertDirCommand.DATE_FORMAT_WINSAFE).parse("2021.02.28-0.01"),
                certificateStatus.revocationDate);
    }
    
    @Test
    public void testImportFromAnotherCA() throws Exception {
        // Import a certificate from another CA. One way to do this is to save the current CA cert, re-create the CA, then import EE cert.
        // Get the CA cert and save it to file
        Certificate caCert = ca.getCACertificate();
        File caCertFile = File.createTempFile("cacert", null, tempDirectory);
        FileOutputStream fileOutputStream = new FileOutputStream(caCertFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(caCert)));
        } finally {
            fileOutputStream.close();
        }
        // Delete the CA
        CaTestUtils.removeCa(authenticationToken, ca.getCAInfo());

        // Create a new CA
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        caSession.addCA(authenticationToken, ca);
        
        // First check that the EE certificate cannot be imported as the current CA's key is different 
        String[] args = new String[] { "DN", CA_NAME, "ACTIVE", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER"};
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNull("Certificate should not have been imported.", endEntityInformation);
        
        // Now check the EE cert can be imported with the --cacert option
        args = new String[] { "DN", CA_NAME, "ACTIVE", tempDirectory.getAbsolutePath(), "--eeprofile", "EMPTY", "--certprofile", "ENDUSER",
                "--cacert", caCertFile.getCanonicalPath()};
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        endEntityInformation = endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN);
        assertNotNull("Certificate was not imported.", endEntityInformation);

        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_GENERATED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate was revoked but should have been Active.", false, certificateStatus.isRevoked());
    }
}
