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
package org.ejbca.ui.web.admin.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import jakarta.annotation.PostConstruct;
import jakarta.ejb.EJB;
import jakarta.faces.FacesException;
import jakarta.faces.component.UIInput;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.context.FacesContext;
import jakarta.faces.model.SelectItem;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Named;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.MutableTriple;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificate.ca.its.ECA;
import org.cesecore.certificate.ca.its.region.ItsGeographicElement;
import org.cesecore.certificate.ca.its.region.ItsGeographicRegion;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaMsCompatibilityIrreversibleException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CitsCaInfo;
import org.cesecore.certificates.ca.CmsCertificatePathMissingException;
import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.cesecore.certificates.ca.ExtendedUserDataHandlerFactory;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.kfenroll.ProxyCaInfo;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.ca.ssh.SshCaInfo;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.PrivateKeyNotExtractableException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.util.SimpleTime;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.attribute.AttributeMapping.REQUEST;
import org.ejbca.ui.web.admin.attribute.AttributeMapping.SESSION;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.cainterface.CaInfoDto;
import org.ejbca.ui.web.admin.certprof.CertProfileBean.ApprovalRequestItem;

import com.keyfactor.CesecoreException;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 *
 * JSF MBean backing the edit ca page.
 *
 */
@Named
@ViewScoped
public class EditCAsMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EditCAsMBean.class);

    private String CRYPTO_TOKEN_LINK = StringUtils.EMPTY;
    
    private static final String INVALID_KEK_ERROR_MESSAGE = "Key encryption key must be set to RSA key to allow key export.";
    private static final HashSet<String> ALLOWED_KEK_TYPES = new HashSet<String>(Arrays.asList(new String[] {"RSA"}));
    private static final String CERTIFICATE_UNAVAILABLE = "Certificate unavailable";
    private final static String HIDDEN_KF_ENROLL_CA_UPSTREAM_PASSWORD = "*********";
    
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private KeyValidatorSessionLocal keyValidatorSession;

    private CAInterfaceBean caBean;
    private String editCaName;
    private int caid = 0;

    private final Map<String,Integer> rootCaProfiles = getEjbcaWebBean().getAuthorizedRootCACertificateProfileNames();
    private final Map<String,Integer> subCaProfiles = getEjbcaWebBean().getAuthorizedSubCACertificateProfileNames();
    //TODO: reconsider if IEEE 1609 RCA is implemented
    private final Map<String,Integer> itsEcaProfiles = getEjbcaWebBean().getAuthorizedItsCACertificateProfileNames();

    private CaInfoDto caInfoDto = new CaInfoDto();
    private boolean isEditCA;

    private int caRevokeReason;
    private String certSignKeyReNewValue;
    private String certExtrSignKeyReNewValue;
    private String certSignKeyRequestValue;
    private boolean checkBoxFutureRollOver;
    private List<String> availableCryptoTokenKeyAliases;
    private List<String> availableCryptoTokenMixedAliases;
    private List<String> availableCryptoTokenEncryptionAliases;
    private List<String> availableCryptoTokenAlternativeKeyAliases;
    private boolean createLinkCertificate;

    private CAInfo cainfo = null;
    private CAToken catoken = null;
    private boolean isCaexternal = false;
    private boolean isCaRevoked = false;
    private Map<Integer, String> keyValidatorMap = getEjbcaWebBean().getEjb().getKeyValidatorSession().getKeyValidatorIdToNameMap();
    private final Map<Integer, String> approvalProfileMap = getEjbcaWebBean().getApprovalProfileIdToNameMap();
    private final TreeMap<String, Integer> certProfilesOfEndEntityType = getEjbcaWebBean().getAuthorizedEndEntityCertificateProfileNames();
    private boolean isUniqueIssuerDnSerialNoIndexPresent;
    private boolean isCvcAvailable;
    private boolean signbyexternal = false;
    private boolean revokable = true;
    private boolean waitingresponse = false;
    private boolean isCaUninitialized = false;
    private List<ApprovalRequestItem> approvalRequestItems = null;

    private boolean suitableCryptoTokenExists;
    private List<SelectItem> availableCryptoTokenSelectItems;
    private List<SelectItem> availableSigningAlgorithmSelectItems;
    private Map<String,String> failedCryptoTokenLinkMap;
    private int currentCryptoTokenId = 0;
    private boolean currentCryptoTokenPresent;
    private String currentCryptoTokenName;
    private String currentCryptoTokenLink;

    private final Map<String, String> aliasUsedMap = new HashMap<>();

    // These two are used in CA life cycle section of edit ca page.
    private boolean cANameChange;
    private String newSubjectDn;


    private GlobalConfiguration globalconfiguration;
    private Map<Integer, String> caIdToNameMap;
    private final Map<String,Integer> caSigners = getEjbcaWebBean().getActiveCANames();
    private final Map<Integer,String> publisheridtonamemap = getEjbcaWebBean().getPublisherIdToNameMapByValue();
    private String crlCaCRLDPExternal;
    private List<String> usedCrlPublishers;
    private Collection<Integer> usedValidators;
    private boolean hideValidity = false;
    private String caCryptoTokenKeyEncryptKey;
    private String caCryptoTokenTestKey;

    private Part fileRecieveFileMakeRequest;
    private Part fileRecieveFileRecieveRequest;
    private Part fileRecieveFileImportRenewal;
    private boolean uploadAsAlternateChain;
    private List<String> alternateChainRoots;
    private Map<String, Boolean> removeAlternateCertChain;

    private String viewCertLink;
    private boolean hasLinkCertificate;
    private String issuerDn = "unknown";
    private Date rolloverNotBefore = null;
    private Date rolloverNotAfter = null;
    private Date caCertNotAfter = null;
    
    private AuthenticationToken administrator;
    
    private List<ItsGeographicRegionGuiWrapper> geographicElementsInGui = null;
    private String currentGeographicRegionType;
    private List<String> geographicRegionTypes;
    
    public List<ItsGeographicRegionGuiWrapper> getGeographicRegions() {
        return geographicElementsInGui;
    }

    public void setGeographicRegions(List<ItsGeographicRegionGuiWrapper> geographicElementsInGui) {
        this.geographicElementsInGui = geographicElementsInGui;
    }
    
    public String getCurrentGeographicRegionType() {
        return currentGeographicRegionType;
    }

    public void setCurrentGeographicRegionType(String currentGeographicRegionType) {
        this.currentGeographicRegionType = currentGeographicRegionType;
    }
    
    public List<String> getGeographicRegionTypes() {
        if(geographicRegionTypes==null) {
            geographicRegionTypes = EditCaUtil.getAllGeographicRegionTypes();
        }
        if(currentGeographicRegionType==null) {
            currentGeographicRegionType = geographicRegionTypes.get(0);
        }
        return geographicRegionTypes;
    }
    
    public String addGeographicRegion() {
        try {
            EditCaUtil.addGeographicRegionGui(currentGeographicRegionType, geographicElementsInGui);
        } catch(Exception e) {
            log.debug(e);
        }
        return "";
    }
    
    public void updateGeographicRegions() {
        EditCaUtil.updateGeographicRegions(geographicElementsInGui);
    }
    
    public String getExpiryTime() {
        Date expireTime = cainfo.getExpireTime();
        if(expireTime==null) {
            return CERTIFICATE_UNAVAILABLE; // TODO: resources
        }
        return caBean.getExpiryTime(expireTime);
    }
    
    public String getCitsHexCertificate() {
        String caCertificate = ((CitsCaInfo)cainfo).getHexEncodedCert();
        if(caCertificate==null) {
            return CERTIFICATE_UNAVAILABLE; // TODO: resources
        }
        StringBuilder formattedCert = new StringBuilder();
        for(int i=0; i<caCertificate.length(); i+=64) {
            formattedCert.append(caCertificate.substring(i, Math.min(i+64, caCertificate.length())));
            formattedCert.append("<br>");
        }
        return formattedCert.toString();
    }
    
    public String getCitsHexCertificateHash() {
        String caCertificateHash = ((CitsCaInfo)cainfo).getHexEncodedCertHash();
        if(caCertificateHash==null) {
            return CERTIFICATE_UNAVAILABLE; // TODO: resources
        }
        return caCertificateHash;
    }

    public Part getFileRecieveFileImportRenewal() {
        return fileRecieveFileImportRenewal;
    }

    public void setFileRecieveFileImportRenewal(final Part fileRecieveFileImportRenewal) {
        this.fileRecieveFileImportRenewal = fileRecieveFileImportRenewal;
    }

    public CaInfoDto getCaInfoDto() {
        return caInfoDto;
    }

    public void setCaInfoDto(CaInfoDto caInfoDto) {
        this.caInfoDto = caInfoDto;
    }

    public Part getFileRecieveFileMakeRequest() {
        return fileRecieveFileMakeRequest;
    }

    public void setFileRecieveFileMakeRequest(final Part fileRecieveFileMakeRequest) {
        this.fileRecieveFileMakeRequest = fileRecieveFileMakeRequest;
    }

    public EditCAsMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CAVIEW.resource());
        globalconfiguration = getEjbcaWebBean().getGlobalConfiguration();
    }

    @PostConstruct
    public void initialize() {
        EditCaUtil.navigateToManageCaPageIfNotPostBack();

        final HttpServletRequest request = (HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest();
        try {
            caBean = SessionBeans.getCaBean(request);
        } catch (ServletException e) {
            throw new IllegalStateException("Could not initiate CAInterfaceBean", e);
        }

        caIdToNameMap = caSession.getCAIdToNameMap();
        isUniqueIssuerDnSerialNoIndexPresent = caBean.isUniqueIssuerDNSerialNoIndexPresent();
        isCvcAvailable = caBean.isCvcAvailable();

        final Map<String, Object> requestMap = FacesContext.getCurrentInstance().getExternalContext().getRequestMap();
        initPageVariables(requestMap);

        viewCertLink = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath() + "viewcertificate.xhtml";

        try {
            cainfo = caBean.getCAInfo(caid).getCAInfo();
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while trying to get the ca info!", e);
        }

        CRYPTO_TOKEN_LINK = getEjbcaWebBean().getBaseUrl() + globalconfiguration.getAdminWebPath()
        + "cryptotoken/cryptotoken.jsf?cryptoTokenId=";

        // Init include health check
        caInfoDto.setIncludeInHealthCheck(cainfo == null || cainfo.getIncludeInHealthCheck());

        // Here we do initialize the sub views.
        if (isEditCA) {
            initEditCaPage();
        } else {
            initCreateCaPage();
        }
        updateKeyAliases();

        // Is this CA is a root CA? Then create link certificate on renewal by default
        createLinkCertificate = cainfo != null && CAInfo.SELFSIGNED == cainfo.getSignedBy();
        
        administrator = getEjbcaWebBean().getAdminObject();
        
    }


    public String getNewSubjectDn() {
        return newSubjectDn;
    }

    public void setNewSubjectDn(final String newSubjectDn) {
        this.newSubjectDn = newSubjectDn;
    }

    public boolean iscANameChange() {
        return cANameChange;
    }

    public void setcANameChange(final boolean cANameChange) {
        this.cANameChange = cANameChange;
    }

    public int getCaid() {
        return caid;
    }

    public void setCaTypeX509() {
        caInfoDto.setCaType(CAInfo.CATYPE_X509);
    }

    public void setCaTypeCVC() {
        caInfoDto.setCaType(CAInfo.CATYPE_CVC);
    }

    public void setCaTypeSSH() {
        caInfoDto.setCaType(CAInfo.CATYPE_SSH);
    }
    
    public void setCaTypeCits() {
        caInfoDto.setCaType(CAInfo.CATYPE_CITS);
    }

    public void setCaTypeProxy() {
        caInfoDto.setCaType(CAInfo.CATYPE_PROXY);
    }

    public String getCurrentCaType() {
        switch (caInfoDto.getCaType()) {
        case CAInfo.CATYPE_X509:
            return "X509";
        case CAInfo.CATYPE_CVC:
            return "CVC";
        case CAInfo.CATYPE_SSH:
            return SshCa.CA_TYPE;
        case CAInfo.CATYPE_CITS:
            return "ECA";
        case CAInfo.CATYPE_PROXY:
            return "Keyfactor Enrollment Proxy CA";
        default:
            return "UNKNOWN";
        }
    }

    public boolean isEditCA() {
        return isEditCA;
    }

    public void setEditCA(final boolean isEditCA) {
        this.isEditCA = isEditCA;
    }

    public String getButtonEditCAValue() {
        return isViewOnly() ? getEjbcaWebBean().getText("VIECA") : getEjbcaWebBean().getText("EDITCA");
    }

    public String getImportKeystoreText() {
        return getEjbcaWebBean().getText("IMPORTCA_KEYSTORE") + "...";
    }

    public String getImportCertificateText() {
        return getEjbcaWebBean().getText("IMPORTCA_CERTIFICATE") + "...";
    }

    public boolean isCanRemoveResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAREMOVE.resource());
    }

    public boolean isCanAddResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource());
    }

    public boolean isCanRenewResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CARENEW.resource());
    }

    public boolean isCanEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }

    public boolean isCanAddOrEditResource() {
        return getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAADD.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource());
    }

    public boolean isCaUninitialized() {
        return isCaUninitialized;
    }

    public boolean isCaExternal() {
        return isCaexternal;
    }

    public boolean isSignByExternal() {
        return signbyexternal;
    }

    public String getCurrentCaSigningAlgorithm() {
        if (this.cainfo != null) {
            final String signAlgorithm = cainfo.getCAToken().getSignatureAlgorithm();
            if (signAlgorithm != null) {
                return signAlgorithm;
            }
            return getEjbcaWebBean().getText("NOTUSED");
        }
        return StringUtils.EMPTY;
    }
    
    public String getCurrentCaAlternativeSigningAlgorithm() {
        if (this.cainfo != null) {
            final String signAlgorithm = cainfo.getCAToken().getAlternativeSignatureAlgorithm();
            if (signAlgorithm != null) {
                return signAlgorithm;
            }
            return getEjbcaWebBean().getText("NOTUSED");
        }
        return StringUtils.EMPTY;
    }

    public String getEditCAPageTitle() {
        if (this.isEditCA && caBean.hasEditRight()) {
            return getEjbcaWebBean().getText("EDITCA");
        } else if (this.isEditCA){
            return getEjbcaWebBean().getText("VIEWCA");
        } else {
            return getEjbcaWebBean().getText("CREATECA");
        }
    }

    public boolean isHasEditRight() {
        return caBean.hasEditRight();
    }

    public boolean isHasCreateRight() {
        return caBean.hasCreateRight();
    }

    public String getCurrentCaCryptoTokenLink() {
        return currentCryptoTokenLink;
    }

    public String getCurrentCaCryptoTokenName() {
        return currentCryptoTokenName;
    }

    public boolean isCurrentCaCryptoTokenPresent() {
        return currentCryptoTokenPresent;
    }

    public String getCurrentCaCryptoTokenDefaultKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT);
            } catch (final CryptoTokenOfflineException e) {
                log.error("Crypto token with id " + catoken.getCryptoTokenId() + " is offline.", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenCertSignKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            } catch (final CryptoTokenOfflineException e) {
                log.error("Crypto token with id " + catoken.getCryptoTokenId() + " is offline.", e);
            }
        }
        return StringUtils.EMPTY;
    }
    
    public String getCurrentCaCryptoTokenAlternativeCertSignKey() {
        if(catoken != null) {
            try {
                if (StringUtils.isNotEmpty(catoken.getAlternativeSignatureAlgorithm())) {
                    return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPUPROSE_ALTERNATIVE_CERTSIGN);
                } else {
                    return getEjbcaWebBean().getText("NOTUSED");
                }
            } catch (final CryptoTokenOfflineException e) {
                log.error("Crypto token with id " + catoken.getCryptoTokenId() + " is offline.", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenCrlSignKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN);
            } catch (final CryptoTokenOfflineException e) {
                log.error("Crypto token with id " + catoken.getCryptoTokenId() + " is offline.", e);
            }
        }
        return StringUtils.EMPTY;
    }

    public String getCurrentCaCryptoTokenKeyEncryptKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
            } catch (final CryptoTokenOfflineException e) {
                log.error("Crypto token with id " + catoken.getCryptoTokenId() + " is offline.", e);
            }
        }
        return this.caCryptoTokenKeyEncryptKey;
    }

    public String getCurrentCaCryptoTokenTestKey() {
        if(catoken != null) {
            try {
                return catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST);
            } catch (final CryptoTokenOfflineException e) {
                log.error("Crypto token with id " + catoken.getCryptoTokenId() + " is offline.", e);
            }
        }
        return this.caCryptoTokenTestKey;
    }

    public String getEditCaName() {
        return " : " + EditCaUtil.getTrimmedName(this.editCaName);
    }

    public String getCreateCaNameTitle() {
        return " : " + caInfoDto.getCaName();
    }

    public List<SelectItem> getKeySequenceFormatList() {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, getEjbcaWebBean().getText("NUMERIC")));
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC, getEjbcaWebBean().getText("ALPHANUMERIC")));
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_NUMERIC, getEjbcaWebBean().getText("COUNTRYCODEPLUSNUMERIC")));
        resultList.add(new SelectItem(StringTools.KEY_SEQUENCE_FORMAT_COUNTRY_CODE_PLUS_ALPHANUMERIC, getEjbcaWebBean().getText("COUNTRYCODEPLUSALPHANUMERIC")));
        return resultList;
    }

    public String getKeySequence() {
        if (catoken != null) {
            caInfoDto.setKeySequence(catoken.getKeySequence());
        }
        return caInfoDto.getKeySequence();
    }

    public void setKeySequence(final String keySequenceValue) {
        caInfoDto.setKeySequence(keySequenceValue);
    }

    public String getCheckboxUseCollapsedText() {
        return getEjbcaWebBean().getText("USE") + "...";
    }

    public String getCaIssuerDN() {
        return issuerDn;
    }

    public String getSignedByAsText() {
        switch (caInfoDto.getSignedBy()) {
        case CAInfo.SELFSIGNED: return getEjbcaWebBean().getText("SELFSIGNED");
        case CAInfo.SIGNEDBYEXTERNALCA: return getEjbcaWebBean().getText("EXTERNALCA");
        default:
            final String caName = caIdToNameMap.get(caInfoDto.getSignedBy());
            if (caName != null) {
                return caName;
            }
            log.warn("Missing signed by CA ID " + caInfoDto.getSignedBy());
            return "Missing CA ID " + caInfoDto.getSignedBy();
        }
    }

    public List<SelectItem> getSignedByList() {
        final List<SelectItem> signedByList = new ArrayList<>();

        signedByList.add(new SelectItem(CAInfo.SELFSIGNED, getEjbcaWebBean().getText("SELFSIGNED"), ""));
        signedByList.add(new SelectItem(CAInfo.SIGNEDBYEXTERNALCA, getEjbcaWebBean().getText("EXTERNALCA"), ""));

        for (final String nameOfCa : caSigners.keySet()) {
            final int entryId = caSigners.get(nameOfCa);
            if (entryId == caid) {
                continue;
            }
            signedByList.add(new SelectItem(entryId, nameOfCa, ""));
        }
        return signedByList;
    }

    public String getCertificateProfileEditCAUninitialized() {
        if (cainfo.getCertificateProfileId() != 0) {
            return certificateProfileSession.getCertificateProfileName(cainfo.getCertificateProfileId());
        }
        return getEjbcaWebBean().getText("NOTUSED");
    }

    public List<SelectItem> getCertificateProfiles() {
        final List<SelectItem> resultList = new ArrayList<>();
        if(isCaTypeCits()) {
            for (final Entry<String, Integer> entry : itsEcaProfiles.entrySet()) {
                resultList.add(new SelectItem(entry.getValue(), entry.getKey()));
            }
        } else if (caInfoDto.getSignedBy() == CAInfo.SELFSIGNED) {
            for (final Entry<String, Integer> entry : rootCaProfiles.entrySet()) {
                resultList.add(new SelectItem(entry.getValue(), entry.getKey()));
            }
        } else if (caInfoDto.getSignedBy() != 0) {
            for (final Entry<String, Integer> entry : subCaProfiles.entrySet()) {
                resultList.add(new SelectItem(entry.getValue(), entry.getKey()));
            }
        }
        return resultList;
    }

    public String getCaEncodedValidity() {
        if (cainfo != null) {
            return cainfo.getEncodedValidity();
        }
        return caInfoDto.getCaEncodedValidity();
    }

    public void setCaEncodedValidity(final String validity) {
        caInfoDto.setCaEncodedValidity(validity);
    }

    public boolean getHideValidity() {
        return hideValidity;
    }

    public boolean isCaTypeCVC() {
        return caInfoDto.getCaType() == CAInfo.CATYPE_CVC;
    }

    public boolean isCaTypeSSH() {
        return caInfoDto.getCaType() == CAInfo.CATYPE_SSH;
    }
    
    public boolean isCaTypeCits() {
        return caInfoDto.getCaType() == CAInfo.CATYPE_CITS;
    }

    public boolean isCaTypeProxy() {
        return caInfoDto.getCaType() == CAInfo.CATYPE_PROXY;
    }

    public String getCaSubjectAltName() {
        return caInfoDto.getCaSubjectAltName();

    }

    public void setCaSubjectAltName(final String subjectAltName) {
        caInfoDto.setCaSubjectAltName(subjectAltName);
    }

    public boolean getWaitingResponse() {
        return this.waitingresponse;
    }

    public void setWaitingResponse(final boolean waitingResponse) {
        this.waitingresponse = waitingResponse;
    }

    public String getCrlCaCRLDPExternal() {
        return this.crlCaCRLDPExternal;
    }

    public void setCrlCaCRLDPExternal(final String crlCaCRLDPExternal) {
        this.crlCaCRLDPExternal = crlCaCRLDPExternal;
    }

    private boolean isEditCaAndCaTypeX509() {
        return isEditCA && caInfoDto.isCaTypeX509();
    }

    public boolean isCheckboxAuthorityKeyIdentifierCriticalDisabled() {
        return isEditCaAndCaTypeX509() && (!caInfoDto.isUseAuthorityKeyIdentifier() || isCaexternal);
    }

    public boolean isCheckboxCrlNumberCriticalDisabled() {
        return isEditCaAndCaTypeX509() && (!caInfoDto.isUseCrlNumber() || isCaexternal);
    }

    public boolean isCheckboxMsCaCompatibilityDisabled() {
        // ECA-10086: A CA that is already using Partitions shouldn't be able made MS Ca Compatible.
        return !caInfoDto.isMsCaCompatible() && caInfoDto.isUsePartitionedCrl();
    }

    public boolean isCheckboxCrlDistributionPointOnCrlCriticalDisabled() {
        return isEditCaAndCaTypeX509() && (!caInfoDto.isUseCrlDistributiOnPointOnCrl() || isCaexternal);
    }

    public boolean isUsePartitionedCrlChecked() {
        final UIInput checkbox = (UIInput) FacesContext.getCurrentInstance().getViewRoot().findComponent(":editcapage:checkboxusecrlpartitions");
        final Boolean submittedValue = (Boolean) checkbox.getSubmittedValue(); // check if there is a changed value (which might not have passed validation)
        return submittedValue != null ? submittedValue : caInfoDto.isUsePartitionedCrl();
    }

    public List<SelectItem> getAvailableCrlPublishers() {
        final List<SelectItem> ret = new ArrayList<>();
        final Set<Integer> publishersIds = publisheridtonamemap.keySet();

        for (final int id: publishersIds) {
            ret.add(new SelectItem(id, publisheridtonamemap.get(id), "", !isHasEditRight()));
        }
        return ret;
    }

    public List<SelectItem> getAvailableRequestPreProcessors() {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(null, "None", "", !isHasEditRight()));
        for (ExtendedUserDataHandler implementation : ExtendedUserDataHandlerFactory.INSTANCE.getAllImplementations()) {
            ret.add(new SelectItem(implementation.getClass().getCanonicalName(), implementation.getReadableName(), implementation.getReadableName(),
                    !isHasEditRight()));
        }
        return ret;
    }

    public List<Integer> getUsedCrlPublishers() {
        Collection<?> usedpublishers = null;
        final List<Integer> ret = new ArrayList<>();
        if (isEditCA) {
            usedpublishers = cainfo.getCRLPublishers();
        }
        final Set<Integer> publishersIds = publisheridtonamemap.keySet();

        for (final int id : publishersIds) {
            if (isEditCA && usedpublishers.contains(id)) {
                ret.add(id);
            }
        }
        return ret;
    }

    public void setUsedCrlPublishers(final List<String> publishers) {
        this.usedCrlPublishers = publishers;
    }

    public void genDefaultCrlDistPoint() {
        final StringBuilder sb = new StringBuilder();
        sb.append(globalconfiguration.getStandardCRLDistributionPointURINoDN());
        if (!isEditCA) {
            sb.append(encode(caInfoDto.getCaSubjectDN()));
        } else {
            sb.append(encode(cainfo.getSubjectDN()));
        }
        if (isUsePartitionedCrlChecked() || caInfoDto.isMsCaCompatible()) {
            sb.append("&partition=*");
        }
        caInfoDto.setDefaultCRLDistPoint(sb.toString());
    }

    private String encode(final String text) {
        try {
            return URLEncoder.encode(text, "UTF-8");
        } catch (final UnsupportedEncodingException e) {
            log.error("Error while encoding text " + text, e);
        }
        return StringUtils.EMPTY;
    }

    public void genDefaultCrlIssuer() {
        if (!isEditCA) {
            caInfoDto.setDefaultCRLIssuer(caInfoDto.getCaSubjectDN());
        } else {
            caInfoDto.setDefaultCRLIssuer(cainfo.getSubjectDN());
        }
    }

    public void genCaDefinedFreshestCrl() {
        final StringBuilder sb = new StringBuilder();
        sb.append(globalconfiguration.getStandardDeltaCRLDistributionPointURINoDN());
        if (!isEditCA) {
            sb.append(encode(caInfoDto.getCaSubjectDN()));
        } else {
            sb.append(encode(cainfo.getSubjectDN()));
        }
        if (isUsePartitionedCrlChecked() || caInfoDto.isMsCaCompatible()) {
            sb.append("&partition=*");
        }
        caInfoDto.setCaDefinedFreshestCRL(sb.toString());
    }

    public void genDefaultOcspLocator() {
        caInfoDto.setDefaultOCSPServiceLocator(globalconfiguration.getStandardOCSPServiceLocatorURI());
    }

    public List<ApprovalRequestItem> getApprovalRequestItems() {
        if (approvalRequestItems == null || approvalRequestItems.isEmpty()) {
            approvalRequestItems = new ArrayList<>();
            final Map<ApprovalRequestType, Integer> approvals = getApprovals();
            for (final ApprovalRequestType approvalRequestType : ApprovalRequestType.values()) {
                int approvalProfileId;
                // Hide ACME approval types (initial CA creation).
                if (ApprovalRequestType.ACMEACCOUNTREGISTRATION.equals(approvalRequestType) 
                 || ApprovalRequestType.ACMEACCOUNTKEYCHANGE.equals(approvalRequestType)) {
                    continue;
                }
                approvalProfileId = approvals.getOrDefault(approvalRequestType, -1);
                approvalRequestItems.add(new ApprovalRequestItem(approvalRequestType, approvalProfileId));
            }
        }
        return approvalRequestItems;
    }

    public void setApprovalRequestItems(final List<ApprovalRequestItem> approvalRequestItems) {
        this.approvalRequestItems = approvalRequestItems;
    }

    public List<SelectItem> getAvailableApprovalProfiles() {
        final List<SelectItem> resultList = new ArrayList<>();
        final List<Integer> approvalProfileIds = getEjbcaWebBean().getSortedApprovalProfileIds();
        for(final Integer approvalProfileId : approvalProfileIds) {
            resultList.add(new SelectItem(approvalProfileId, approvalProfileMap.get(approvalProfileId)));
        }
        return resultList;
    }

    public List<SelectItem> getAvailableValidators() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final int validatorId : keyValidatorMap.keySet()) {
                ret.add(new SelectItem(validatorId, keyValidatorMap.get(validatorId), "", !isHasEditRight()));
        }
        ret.sort((o1, o2) -> o1.getLabel().compareToIgnoreCase(o2.getLabel()));
        return ret;
    }

    public Collection<Integer> getUsedValidators() {
        return usedValidators;
    }

    public void setUsedValidators(final Collection<Integer> validators) {
        this.usedValidators = validators;
    }

    public boolean isWaitingForResponse() {
        return this.waitingresponse;
    }

    public boolean isRenderCaLifeCycle() {
        return isEditCA && isHasEditRight() && revokable;
    }

    public List<SelectItem> getRevokeReasonList() {
        return Arrays.stream(RevocationReasons.values())
                .filter(reason -> reason != RevocationReasons.CERTIFICATEHOLD)
                .filter(reason -> reason != RevocationReasons.REMOVEFROMCRL)
                .filter(reason -> reason != RevocationReasons.NOT_REVOKED)
                .map(reason -> new SelectItem(reason.getDatabaseValue(), reason.getHumanReadable()))
                .collect(Collectors.toList());
    }

    public int getCaRevokeReason() {
        return caRevokeReason;
    }

    public void setCaRevokeReason(final int caRevokeReason) {
        this.caRevokeReason = caRevokeReason;
    }

    public List<SelectItem> getExtrAndCertSignKeyReNewList() {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("RENEWCA_USINGKEYSEQUENCE")));
        for (final String alias : availableCryptoTokenKeyAliases) {
            resultList.add(new SelectItem(alias, alias, ""));
        }
        return resultList;
    }

    public List<SelectItem> getCertSignKeyRecieveReqList() {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("REKEYCA_AUTODETECT")));
        for (final String alias : availableCryptoTokenKeyAliases) {
            resultList.add(new SelectItem(alias, alias, ""));
        }
        return resultList;
    }

    public String getCertSignKeyReNewValue() {
        return this.certSignKeyReNewValue;
    }

    public void setCertSignKeyReNewValue(final String certSignKeyReNewValue) {
        this.certSignKeyReNewValue = certSignKeyReNewValue;
    }

    public String getCertSignKeyRecieveReqValue() {
        return this.certSignKeyRequestValue;
    }

    public void setCertSignKeyRecieveReqValue(final String certSignKeyRequestValue) {
        this.certSignKeyRequestValue = certSignKeyRequestValue;
    }

    public String getExtrCertSignKeyReNewValue() {
        return this.certExtrSignKeyReNewValue;
    }

    public void setExtrCertSignKeyReNewValue(final String certExtrSignKeyReNewValue) {
        this.certExtrSignKeyReNewValue = certExtrSignKeyReNewValue;
    }

    public boolean isRenderUseCaNameChange() {
        if (cainfo != null) {
            return caInfoDto.isCaTypeX509() && cainfo.getSignedBy() == CAInfo.SELFSIGNED && globalconfiguration.getEnableIcaoCANameChange();
        }
        return false;
    }

    public String getNewSubjectDNValue() {
        if (cainfo != null) {
            return cainfo.getSubjectDN();
        }
        return StringUtils.EMPTY;
    }

    public String getBinaryCaIdLink() {
        return EditCaUtil.LINK_CERT_BASE_URI + "format=binary&caid=" + caid;
    }

    public String getCaIdLink() {
        return EditCaUtil.LINK_CERT_BASE_URI + "caid=" + caid;
    }

    public boolean isRenderLinkCertificate() {
        return hasLinkCertificate;
    }

    public boolean isRollOverDate() {
        return rolloverNotBefore != null;
    }

    public String getCaNotAfter() {
        return caCertNotAfter != null ? getEjbcaWebBean().formatAsISO8601(caCertNotAfter) : StringUtils.EMPTY;
    }

    public String getCaRollOverNotBefore() {
        return rolloverNotBefore != null ? getEjbcaWebBean().formatAsISO8601(rolloverNotBefore) : StringUtils.EMPTY;
    }
    public String getCaRollOverNotAfter() {
        return rolloverNotAfter != null ? getEjbcaWebBean().formatAsISO8601(rolloverNotAfter) : StringUtils.EMPTY;
    }

    public String getConfirmRolloverDate() {
        final Date now = new Date();
        if (rolloverNotBefore != null) {
            return rolloverNotBefore.after(now) ? " onclick=\"return confirm('Next certificate is not yet valid! Are you sure?')\"" : StringUtils.EMPTY;
        }
        return StringUtils.EMPTY;
    }

    public boolean isRenderRepublishCA() {
        return isEditCA && !isCaexternal && !waitingresponse && isHasEditRight();
    }

    public boolean isCheckBoxFutureRollOver() {
        return checkBoxFutureRollOver;
    }

    public void setCheckBoxFutureRollOver(final boolean checkBoxFutureRollOver) {
        this.checkBoxFutureRollOver = checkBoxFutureRollOver;
    }

    public boolean isRenderFutureRollOver() {
        return caInfoDto.isCaTypeX509() && !isWaitingForResponse();
    }

    public boolean isCaExportable() {
        return caBean.isCaExportable(cainfo);
    }

    public boolean isEditCANotUninitializedNotExternal() {
        return isEditCA && !isCaUninitialized && !isCaexternal;
    }

    public List<SelectItem> getAvailableSigningAlgList() {
        final List<SelectItem> resultList = new ArrayList<>();
        if(isCaTypeCits()) {
            resultList.add(new SelectItem(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, 
                                        AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, ""));
            resultList.add(new SelectItem(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, 
                                        AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA, ""));
            return resultList;
        } 
        final String cryptoTokenIdParam = caInfoDto.getCryptoTokenIdParam();

        for (final String current : AlgorithmConstants.AVAILABLE_SIGALGS) {
            if (!AlgorithmTools.isSigAlgEnabled(current)) {
                continue; // e.g. GOST3410 if not configured
            }
            resultList.add(new SelectItem(current, current, ""));
        }

        // There is no information to filter signing algorithms by.
        if (!StringUtils.isEmpty(cryptoTokenIdParam) && !cryptoTokenIdParam.equals(CAInterfaceBean.PLACEHOLDER_CRYPTO_TOKEN_ID + "")) {
            try {
                final List<KeyPairInfo> cryptoTokenKeyPairInfos = cryptoTokenManagementSession.getKeyPairInfos(getAdmin(), Integer.parseInt(cryptoTokenIdParam));
                return resultList.stream()
                                 .filter(sa -> getSigningAlgorithmsApplicableForCryptoToken(sa.getLabel(), cryptoTokenKeyPairInfos))
                                 .collect(Collectors.toList());
            } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                log.error("Crypto token key pair infos could not be fetched.", e);
            }
        }

        return resultList;
    }
    
    public List<SelectItem> getAvailableSigningAlgListNoneOption() {
        final List<SelectItem> resultList = getAvailableSigningAlgList();
        resultList.add(0, new SelectItem(null, getEjbcaWebBean().getText("SIGNINGALGORITHM_ALTERNATIVE_NONE")));
        return resultList;
    }

    /**
     * Check if given signing algorithm can be found in crypto token keys.
     *
     * @param signingAlgorithm Signing algorithm
     * @param cryptoTokenKeyPairInfos Key pairs in a crypto token
     * @return true if found
     */
    private boolean getSigningAlgorithmsApplicableForCryptoToken(String signingAlgorithm, List<KeyPairInfo> cryptoTokenKeyPairInfos) {
        String requiredKeyAlgorithm = AlgorithmTools.getKeyAlgorithmFromSigAlg(signingAlgorithm);
        for (final KeyPairInfo cryptoTokenKeyPairInfo : cryptoTokenKeyPairInfos) {
            if (requiredKeyAlgorithm.equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Return a list of values that describe the key pairs in selected
     * Crypto Token.
     *
     * @return list of description i.e. ["defaultKey - RSA 2048", "testKey - RSA 1024"]
     */
    public List<String> getSelectedCryptoTokenInfo() {
        final String cryptoTokenIdParam = caInfoDto.getCryptoTokenIdParam();
        final List<String> keys = new ArrayList<>();

        if (!StringUtils.isEmpty(cryptoTokenIdParam) && !cryptoTokenIdParam.equals("0")){
            try {
                final List<KeyPairInfo> cryptoTokenKeyPairInfos = cryptoTokenManagementSession.getKeyPairInfos(getAdmin(), Integer.parseInt(cryptoTokenIdParam));
                for (KeyPairInfo keyPair : cryptoTokenKeyPairInfos) {
                    keys.add(String.format("%s - %s %s", keyPair.getAlias(), keyPair.getKeyAlgorithm(), keyPair.getKeySpecification()));
                }
            } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                log.error("Crypto token key pair infos could not be fetched.", e);
            }
        }

        Collections.sort(keys);
        return keys;
    }

    public boolean isCryptoTokenSuitable() {
        return suitableCryptoTokenExists;
    }

    public List<SelectItem> getAvailableCryptoTokenList() {
        return availableCryptoTokenSelectItems;
    }

    public boolean isCryptoTokenNeedExistingOrGen() {
        return (isCryptoTokenIdParamNull() && !isCaUninitialized);
    }

    public boolean isCryptoTokenIdParamNull() {
        return caInfoDto.getCryptoTokenIdParam() == null;
    }

    public boolean isCryptoTokenIdParamNotNull() {
        return caInfoDto.getCryptoTokenIdParam() != null;
    }

    public boolean isFailedCryptoTokenExist() {
        return failedCryptoTokenLinkMap != null && !failedCryptoTokenLinkMap.isEmpty();
    }

    public ArrayList<String> getFailedCryptoTokenNames() {
        return new ArrayList<String>(failedCryptoTokenLinkMap.values());
    }


    public String getCryptoTokenIdParam() {
        return caInfoDto.getCryptoTokenIdParam();
    }

    public void setCryptoTokenIdParam(final String cryptoTokenIdParam) {
        caInfoDto.setCryptoTokenIdParam(cryptoTokenIdParam);
        // Create already in use key map
        if (!isEditCA || isCaUninitialized) {
            updateKeyAliases();
        }
    }

    public String getSignatureAlgorithmParam() {
        return caInfoDto.getSignatureAlgorithmParam();
    }

    public void setSignatureAlgorithmParam(final String signatureAlgorithmParam) {
        caInfoDto.setSignatureAlgorithmParam(signatureAlgorithmParam);

        // Create already in use key map
        if (!isEditCA || isCaUninitialized) {
            updateKeyAliases();
        }
    }
    
    public String getAlternativeSignatureAlgorithmParam() {
        return caInfoDto.getAlternativeSignatureAlgorithmParam();
    }
    

    public void setAlternativeSignatureAlgorithmParam(final String alternativeSignatureAlgorithmParam) {
        caInfoDto.setAlternativeSignatureAlgorithmParam(alternativeSignatureAlgorithmParam);

        if(StringUtils.isEmpty(alternativeSignatureAlgorithmParam)) {
            caInfoDto.setCryptoTokenAlternativeCertSignKey(StringUtils.EMPTY);
        }
        
        // Create already in use key map
        if (!isEditCA || isCaUninitialized) {
            updateKeyAliases();
        }
    }
    
    public boolean isAlternativeSignatureAlgorithmSelected() {
        return StringUtils.isNotBlank(caInfoDto.getAlternativeSignatureAlgorithmParam());
    }

    private void setDefaultKeyAliases() {
        // Make up defaults based on key alias names
        caInfoDto.setSelectedKeyEncryptKey("");
        caInfoDto.setTestKey("");

        for (final String alias : availableCryptoTokenEncryptionAliases) {
            if (CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "default")) {
                caInfoDto.setCryptoTokenDefaultKey(alias);
            } else if (CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "sign")) {
                caInfoDto.setCryptoTokenCertSignKey(alias);
            } else if (StringUtils.containsIgnoreCase(alias, "test")) {
                caInfoDto.setTestKey(alias);
            }
        }

        for (final String alias : availableCryptoTokenKeyAliases) {
            if (CAToken.SOFTPRIVATEDECKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "default")) {
                caInfoDto.setCryptoTokenDefaultKey(alias);
            } else if (CAToken.SOFTPRIVATESIGNKEYALIAS.equals(alias) || StringUtils.containsIgnoreCase(alias, "sign"))  {
                caInfoDto.setCryptoTokenCertSignKey(alias);
            } else if (StringUtils.containsIgnoreCase(alias, "test")) {
                caInfoDto.setTestKey(alias);
            }
        }
    }

    private void setKeyAliasesFromCa() throws CryptoTokenOfflineException {
        caInfoDto.setCryptoTokenDefaultKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT));
        caInfoDto.setCryptoTokenCertSignKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        caInfoDto.setSelectedKeyEncryptKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
        caInfoDto.setTestKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
        // For renewal
        certSignKeyRequestValue = "";
        certExtrSignKeyReNewValue = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        certSignKeyReNewValue = catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
    }

    public List<SelectItem> getKeyAliasesList(final String keyType) {
        final List<SelectItem> resultList = new ArrayList<>();
        switch (keyType) {
        case CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING:
            for (final String alias : availableCryptoTokenMixedAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;
        case CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING:
        case CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING:    
            for (final String alias : availableCryptoTokenKeyAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;
        case CATokenConstants.CAKEYPURPOSE_ALTERNATIVE_CERTSIGN_STRING:
            for (final String alias : availableCryptoTokenAlternativeKeyAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;     
        case CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING:
            for (final String alias : availableCryptoTokenEncryptionAliases) {
                resultList.add(new SelectItem(alias, alias + aliasUsedMap.get(alias), ""));
            }
            return resultList;
        default:
            return Collections.emptyList();
        }
    }

    public List<SelectItem> getKeyAliasesListWithDefault(final String keyType) {
        final List<SelectItem> resultList = new ArrayList<>();
        resultList.add(new SelectItem(StringUtils.EMPTY, getEjbcaWebBean().getText("CRYPTOTOKEN_DEFAULTKEY")));
        resultList.addAll(getKeyAliasesList(keyType));
        return resultList;
    }

    public String getSelectedCryptoTokenDefaultKey() {
        return caInfoDto.getCryptoTokenDefaultKey();
    }

    public void setSelectedCryptoTokenDefaultKey(final String selectedCryptoTokenDefaultKey) {
        caInfoDto.setCryptoTokenDefaultKey(StringUtils.defaultString(selectedCryptoTokenDefaultKey));
    }

    public boolean isRenderCreateCaTokenKeys() {
        if (!isEditCA || isCaUninitialized) {
            return (!isCryptoTokenIdParamNull() && !caInfoDto.getCryptoTokenIdParam().isEmpty() && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0);
        }
        return false;
    }

    public String getSelectedCryptoTokenCertSignKey() {
        return caInfoDto.getCryptoTokenCertSignKey();
    }

    public void setSelectedCryptoTokenCertSignKey(final String selectedCryptoTokenCertSignKey) {
        caInfoDto.setCryptoTokenCertSignKey(StringUtils.defaultString(selectedCryptoTokenCertSignKey));
    }
    
    public String getSelectedCryptoTokenAlternativeCertSignKey() {
        if (StringUtils.isNotEmpty(caInfoDto.getAlternativeSignatureAlgorithmParam())) {
            return caInfoDto.getCryptoTokenAlternativeCertSignKey();
        } else {
            return getEjbcaWebBean().getText("NOTUSED");
        }
    }

    public void setSelectedCryptoTokenAlternativeCertSignKey(final String selectedCryptoTokenAlternativeCertSignKey) {
        caInfoDto.setCryptoTokenAlternativeCertSignKey(StringUtils.defaultString(selectedCryptoTokenAlternativeCertSignKey));
    }

    public String getSelectedKeyEncryptKey() {
        return caInfoDto.getSelectedKeyEncryptKey();
    }

    public void setSelectedKeyEncryptKey(final String selectedKeyEncryptKey) {
        caInfoDto.setSelectedKeyEncryptKey(StringUtils.defaultString(selectedKeyEncryptKey));
    }

    public String getSelectTestKey() {
        return caInfoDto.getTestKey();
    }

    public void setSelectTestKey(final String testKey) {
        caInfoDto.setTestKey(StringUtils.defaultString(testKey));
    }

    public String getCertificateValidityHelp() {
        return getEjbcaWebBean().getText("DATE_HELP") + "=" + getEjbcaWebBean().getDateExample() + "." + getEjbcaWebBean().getText("YEAR365DAYS")
                + ", " + getEjbcaWebBean().getText("MO30DAYS");
    }

    public boolean isRenderSaveExternalCa() {
        return (caInfoDto.isCaTypeX509() || caInfoDto.isCaTypeProxy()) && isHasEditRight();
    }

    public boolean isRenderRenewCA() {
        final int cryptoTokenId = catoken == null ? currentCryptoTokenId : catoken.getCryptoTokenId();
        try {
            return isEditCA && !isCaexternal && !waitingresponse &&
                    cryptoTokenManagementSession.isCryptoTokenPresent(getAdmin(), cryptoTokenId) &&
                    cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId) &&
                    cainfo.getSignedBy()!=CAInfo.SIGNEDBYEXTERNALCA && !isCaRevoked;
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while accessing ca bean!", e);
        }
        return false;
    }

    public boolean isRenderNameConstraintsWarning() {
        if (isEditCA) {
            String certProfileName = caInfoDto.getCurrentCertProfile();
            if (StringUtils.isNotBlank(certProfileName)) {
                CertificateProfile cp = certificateProfileSession.getCertificateProfile(certProfileName);
                if (Objects.nonNull(cp)) {
                    return !cp.getUseNameConstraints();
                } else {
                    return true;
                }
            } else {
                return true;
            }
        } else {
            String certProfileId = caInfoDto.getCurrentCertProfile();
            if (Objects.nonNull(certProfileId)) {
                if (Objects.nonNull(certProfileId)) {
                    CertificateProfile cp = certificateProfileSession.getCertificateProfile(Integer.valueOf(certProfileId));
                    if (Objects.nonNull(cp)) {
                        return !cp.getUseNameConstraints();
                    } else {
                        return true;
                    }
                } else {
                    return true;
                }
            } else {
                return true;
            }
        }
    }

    public boolean isRenderSelectCertificateProfile() {
        return !isEditCA || isCaUninitialized;
    }

    public boolean isRenderOcspPreProduction() {
        return getEjbcaWebBean().isRunningEnterprise();
    }

    public String getCaCertLink() {
        return viewCertLink + "?caid=" + caid;
    }

    public boolean isEditCaUninitializedHasEditRights() {
        return isEditCA && isCaUninitialized && isHasEditRight();
    }

    public boolean isEditCaNotUninitializedHasEditRights() {
        return isEditCA && !isCaUninitialized && isHasEditRight();
    }

    public  boolean isAuthorityKeyIdentifierValidated(){
        return caInfoDto.isMsCaCompatible();
    }

    public boolean isIssuingDistributionPointValidated() {
        return caInfoDto.isUsePartitionedCrl() || caInfoDto.isMsCaCompatible();
    }

    public boolean isDefaultCRLDistributionPointValidated() {
        return caInfoDto.isUsePartitionedCrl() || caInfoDto.isMsCaCompatible();
    }

    public boolean isCheckboxAcceptRevocationsNonExistingEntryDisabled() {
        return (!isHasEditRight() || caInfoDto.isUseCertificateStorage());
    }

    public boolean isCertificateProfileForNonExistingDisabled(){
        return (!isHasEditRight() || caInfoDto.isUseCertificateStorage() || !caInfoDto.isAcceptRevocationsNonExistingEntry());
    }

    public List<SelectItem> getThrowAwayDefaultProfileList() {
        final List<SelectItem> resultList = new ArrayList<>();
        for (final String profilename : certProfilesOfEndEntityType.keySet()) {
            final int certprofid = certProfilesOfEndEntityType.get(profilename);
            resultList.add(new SelectItem(certprofid, profilename, "", isCertificateProfileForNonExistingDisabled()));
        }
        return resultList;
    }

    public boolean isRenderCvcAvailable() {
        return (caInfoDto.getCaType() == CAInfo.CATYPE_CVC) && (!isCvcAvailable || isUniqueIssuerDnSerialNoIndexPresent);
    }

    public boolean isRenderSshAvailable() {
        return CAFactory.INSTANCE.existsCaType(SshCa.CA_TYPE);
    }

    public boolean isRenderCitsAvailable() {
        return CAFactory.INSTANCE.existsCaType(ECA.CA_TYPE);
    }
    
    public boolean isCvcAvailable() {
        return isCvcAvailable;
    }


    public boolean isRenderExternallySignedCaCreationRenewal() {
        final int cryptoTokenId = catoken == null ? currentCryptoTokenId : catoken.getCryptoTokenId();
        if(isCaTypeCits()) {
            // currentCryptoTokenId is 0 only if no suitable token is present
            // for all other CAs any token is suitable + due to ManagementCA in CA at least one token is present
            // but for ECA(not ITS) we need 2 EC keys of same type
            return isHasEditRight();
        }
        try {
            return !isCaTypeSSH() && !isCaexternal && cryptoTokenManagementSession.isCryptoTokenPresent(getAdmin(), cryptoTokenId) &&
                    cryptoTokenManagementSession.isCryptoTokenStatusActive(getAdmin(), cryptoTokenId) &&
                    isHasEditRight();
        } catch (final AuthorizationDeniedException e) {
            log.error("Error calling ca bean!", e);
        }
        return false;
    }

    public Part getFileRecieveFileRecieveRequest() {
        return fileRecieveFileRecieveRequest;
    }

    public void setFileRecieveFileRecieveRequest(final Part fileRecieveFileRecieveRequest) {
        this.fileRecieveFileRecieveRequest = fileRecieveFileRecieveRequest;
    }

    public boolean isSignedByExternal() {
        return caInfoDto.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA;
    }

    public void resetSignedBy() {
        caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
        updateAvailableCryptoTokenList();
        updateAvailableSigningAlgorithmList();
    }
    
    public void renderCitsFields() {
        caInfoDto.setCaType(CAInfo.CATYPE_CITS);
        caInfoDto.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
        updateAvailableCryptoTokenList(true);
        updateAvailableSigningAlgorithmList();
        getCertificateProfiles();
        geographicElementsInGui = new ArrayList<>();
    }

    public void renderProxyCaFields() {
        caInfoDto.setCaType(CAInfo.CATYPE_PROXY);
        caInfoDto.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
        //caInfoDto.setSignedBy(CAInfo.SELFSIGNED); // TODO: just for testing, it must be CAInfo.SIGNEDBYEXTERNALCA, details about the upstream CA will make things correctly implementable
//        updateAvailableCryptoTokenList(false); // TODO: Not sure if true or false. cryptoToken field has to disabled once we get details about the upstream CA
//        updateAvailableSigningAlgorithmList();
//        getCertificateProfiles();
    }

    public boolean isCreateLinkCertificate() {
        return createLinkCertificate;
    }

    public void setCreateLinkCertificate(final boolean createLinkCertificate) {
        this.createLinkCertificate = createLinkCertificate;
    }

    public void resetSigningAlgorithmTokenParam() {
        caInfoDto.setSignatureAlgorithmParam(StringUtils.EMPTY);
        caInfoDto.setAlternativeSignatureAlgorithmParam(StringUtils.EMPTY);
        updateAvailableSigningAlgorithmList();

        // Create already in use key map
        if (!isEditCA || isCaUninitialized) {
            updateKeyAliases();
        }
    }
    
    /**
     * We want to make sure that a subca created under a rootca is a hybrid ca if the rootca is a hybrid ca
     * We want to make sure that a subca created under a rootca is a non hybrid ca if the rootca is a non hybrid ca
     * @return true if the chain is mixed and the ca cannot be created
     */
    public boolean isMixedHybridChain() {
        String alternativeSignature = getAlternativeSignatureAlgorithmParam();
        int signerCaId  = caInfoDto.getSignedBy();
        boolean creatingSelfSignedCa = (signerCaId == CAInfo.SELFSIGNED) ? true : false;
        CAToken signerCaToken = null;
        String signerAlternativeSignature = null;
        if (!creatingSelfSignedCa) {
            signerCaToken = caSession.getCAInfoInternal(signerCaId).getCAToken();
            signerAlternativeSignature = signerCaToken.getAlternativeSignatureAlgorithm();
        }            
        if (!creatingSelfSignedCa && ((alternativeSignature == null) && (signerAlternativeSignature != null) )) {
            addErrorMessage("ERROR_NON_HYBRID_SUBCA_UNDER_HYBRID_ROOTCA");
            return true;
        }
        if (!creatingSelfSignedCa && (alternativeSignature != null && signerAlternativeSignature == null )) {
            addErrorMessage("ERROR_HYBRID_SUBCA_UNDER_NON_HYBRID_ROOTCA");
            return true;
        }
        return false;
    }

    // ===================================================== Create CA Actions ============================================= //

    /**
     * Ca creation button pressed
     * @return Navigation
     */
    public String createCa() {
        if(isMixedHybridChain())  return "";
        return createCaOrMakeRequest(true, false); // We are creating a ca!
    }

    /**
     * This one used by both edit and create ca pages.
     * @return Navigation
     */
    public String makeRequest() {
        if (isEditCA) {
            return makeRequestEditCa();
        }
        return createCaOrMakeRequest(false, true); // We are making a request!
    }

    public String cancel() {
        return EditCaUtil.MANAGE_CA_NAV;
    }
    
    // ======================================= Helpers ===================================================================//
    private String createCaOrMakeRequest(final boolean createCa, final boolean makeRequest) {
        boolean illegalDnOrAltName;
        byte[] fileBuffer = null;
        try {
            if (makeRequest) {
                if (isCaTypeCits()) {
                    // only applicable to externally signed ca
                    try {
                        caInfoDto.setCaSubjectDN(CAInfo.CITS_SUBJECTDN_PREFIX + caInfoDto.getCertificateId());
                        ItsGeographicElement geoElement = EditCaUtil.getGeographicRegion(currentGeographicRegionType, geographicElementsInGui);
                        if (geoElement != null) {
                            log.info("Region: '" + geoElement.toStringFormat() + "'");
                            caInfoDto.setRegion(geoElement.toStringFormat());
                        }
                    } catch (final Exception e) {
                        addNonTranslatedErrorMessage(e);
                        return "";
                    }
                }
                if (fileRecieveFileMakeRequest != null) {
                    fileBuffer = IOUtils.toByteArray(fileRecieveFileMakeRequest.getInputStream(), fileRecieveFileMakeRequest.getSize());
                }
            }

            illegalDnOrAltName = saveOrCreateCaInternal(createCa, makeRequest, fileBuffer);
            if (illegalDnOrAltName) {
                addErrorMessage("INVALIDSUBJECTDN");
            } 
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }

        final long crlperiod = SimpleTime.getInstance(caInfoDto.getCrlCaCrlPeriod(), "0" + SimpleTime.TYPE_MINUTES).getLong();

        if (caInfoDto.isCaTypeX509() && crlperiod != 0 && !illegalDnOrAltName && createCa) {
            return EditCaUtil.MANAGE_CA_NAV;
        }
        if (caInfoDto.getCaType() == CAInfo.CATYPE_CVC && !illegalDnOrAltName && createCa) {
            caid = DnComponents.stringToBCDNString(caInfoDto.getCaSubjectDN()).hashCode();
            return EditCaUtil.MANAGE_CA_NAV;
        }

        if (makeRequest && !illegalDnOrAltName) {
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caname", caInfoDto.getCaName());
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caType", caInfoDto.getCaType());
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("filemode", EditCaUtil.CERTREQGENMODE);
            FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put(SESSION.CA_INTERFACE_BEAN, caBean);
            return EditCaUtil.DISPLAY_RESULT_NAV;
        }
        return EditCaUtil.MANAGE_CA_NAV;
    }

    private boolean saveOrCreateCaInternal(final boolean createCa, final boolean makeRequest, final byte[] fileBuffer)
            throws Exception {
       return caBean.actionCreateCaMakeRequest(caInfoDto, getApprovals(), getAvailablePublisherValues(),
                    getAvailableKeyValidatorValues(), createCa, makeRequest, fileBuffer);
    }

    // ===================================================== Create CA Actions ============================================= //
    // ===================================================== Edit CA Actions =============================================== //

    /**
     * Renews a ca
     * @return navigates back to manage ca page if successful.
     */
    public String renewCa() {
        try {
            if (caSession.getCAInfo(getAdmin(), caid).getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                addNonTranslatedErrorMessage("Cannot renew an externally signed CA."); // Button should not even be available in this case
                return "";
            }
            if (cANameChange && newSubjectDn != null && !newSubjectDn.isEmpty()) {
                renewAndRenameCA(caid, certSignKeyReNewValue, createLinkCertificate, newSubjectDn);
            } else {
                renewCA(caid, certSignKeyReNewValue, createLinkCertificate);
            }
            addInfoMessage(getEjbcaWebBean().getText("CARENEWED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }
    
    private void renewCA(int caid, String nextSignKeyAlias, boolean createLinkCertificate) throws Exception {
        if (caSession.getCAInfo(administrator, caid).getCAType() == CAInfo.CATYPE_CVC) {
            // Force generation of link certificate for CVC CAs
            createLinkCertificate = true;
        }
        if (nextSignKeyAlias == null || nextSignKeyAlias.length()==0) {
            // Generate new keys
            caAdminSession.renewCA(administrator, caid, true, null, createLinkCertificate);
        } else {
            // Use existing keys
            caAdminSession.renewCA(administrator, caid, nextSignKeyAlias, null, createLinkCertificate);
        }
    }
    
    private void renewAndRenameCA(int caid, String nextSignKeyAlias, boolean createLinkCertificate, String newSubjectDn) throws Exception {
        if (nextSignKeyAlias == null || nextSignKeyAlias.length()==0) {
            // Generate new keys
            caAdminSession.renewCANewSubjectDn(administrator, caid, true, null, createLinkCertificate, newSubjectDn);
        } else {
            // Use existing keys
            caAdminSession.renewCANewSubjectDn(administrator, caid, nextSignKeyAlias, null, createLinkCertificate, newSubjectDn);
        }
    }

    /**
     * Revoke a ca (in editca page) and navigates back to the managecas.xhtml
     * @return navigation
     */
    public String revokeCa() {
        try {
            caAdminSession.revokeCA(getAdmin(), caid, caRevokeReason);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Saves external ca (in edit ca page) and navigates back to managecas.xhtml
     * @return Navigation
     */
    public String saveExternalCA() {
        if (caInfoDto.getCaType()==CAInfo.CATYPE_X509) {
            final X509CAInfo x509caInfo = (X509CAInfo)cainfo;
            x509caInfo.setExternalCdp(crlCaCRLDPExternal.trim());
            x509caInfo.setAllowInvalidityDate(caInfoDto.isAllowInvalidityDate());
            x509caInfo.setDoPreProduceOcspResponses(caInfoDto.isDoPreProduceOcspResponses());
            x509caInfo.setDoStoreOcspResponsesOnDemand(caInfoDto.isDoStoreOcspResponsesOnDemand());
            x509caInfo.setDoPreProduceOcspResponseUponIssuanceAndRevocation(caInfoDto.isDoPreProduceOcspResponseUponIssuanceAndRevocation());
            return saveCaInternal(x509caInfo);
        } else if (caInfoDto.getCaType()==CAInfo.CATYPE_PROXY) {
            return saveCaInternal(caInfoDto.buildProxyCaInfo());
        }
        return "";
    }

    /**
     * Initialize a ca (in editca page) and navigates back to managecas.xhtml if successful.
     * The CA status is set to active and certificates are generated.
     * @return Navigation
     */
    public String initializeCa() {
        try {
            final CAInfo cainfo = getCaInfo();
            final int certprofileid = (caInfoDto.getCurrentCertProfile() == null ? 0 : Integer.parseInt(caInfoDto.getCurrentCertProfile()));
            cainfo.setSignedBy(caInfoDto.getSignedBy());
            cainfo.setCertificateProfileId(certprofileid);
            cainfo.setDefaultCertificateProfileId(caInfoDto.getDefaultCertProfileId());
            cainfo.setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData());
            CAInfo oldinfo = caSession.getCAInfo(getAdmin(), cainfo.getCAId());
            cainfo.setName(oldinfo.getName());
            caAdminSession.initializeCa(getAdmin(), cainfo);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CryptoTokenOfflineException | InvalidAlgorithmException | NumberFormatException | AuthorizationDeniedException | InternalKeyBindingNonceConflictException | CaMsCompatibilityIrreversibleException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Save changes in the ca (in editca page) and navigates back to managecas.xhtml if successful.
     * @return Navigation
     */
    public String saveCa() {
        try {
            final CAInfo caInfo = getCaInfo();
            if (caInfo == null) {
                // Error already added by getCaInfo
                return "";
            }
            return saveCaInternal(caInfo);
        } catch (NumberFormatException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Republishs a ca and navigates back to manageca page with the result if successful.
     * @return Navigation
     */
    public String publishCA() {
        try {
            caAdminSession.publishCA(getAdmin(), caid);
            addInfoMessage(getEjbcaWebBean().getText("CACERTPUBLISHINGQUEUED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    /**
     * Rollovers a ca and navigates back to manageca page if successful.
     *
     * @return Navigation
     */
    public String rolloverCA() {
        try {
            caAdminSession.rolloverCA(getAdmin(), caid);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }
    
    public boolean isUploadAsAlternateChain() {
        return uploadAsAlternateChain;
    }

    public void setUploadAsAlternateChain(boolean uploadAsAlternateChain) {
        this.uploadAsAlternateChain = uploadAsAlternateChain;
    }
    
    public String escapeDnString(String subjectDn) {
        try {
            return URLEncoder.encode(subjectDn, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            // NOPMD
            log.error("Error while encoding subjectDn: ", e);
            return null;
        }
    }
    
    public List<String> getAlternateCertChains(){
        if(alternateChainRoots!=null) {
            return alternateChainRoots;
        }
        removeAlternateCertChain = new HashMap<>();
        if(isEditCaAndCaTypeX509() && ((X509CAInfo)cainfo).getAlternateCertificateChains()!=null) {
            alternateChainRoots = new ArrayList<>(caInfoDto.getAlternateCertificateChains().keySet());
            for (String alias: alternateChainRoots) {
                removeAlternateCertChain.put(alias, false);
            }
        } else {
            alternateChainRoots = new ArrayList<>();
        }
        return alternateChainRoots;
    }
        
    public Map<String, Boolean> getRemoveAlternateCertChain() {
        return removeAlternateCertChain;
    }

    public void setRemoveAlternateCertChain(Map<String, Boolean> removeAlternateCertChain) {
        this.removeAlternateCertChain = removeAlternateCertChain;
    }

    public void unlinkAlternateCertChains() {
        for (Entry<String, Boolean> altChain: removeAlternateCertChain.entrySet()) {
            if (altChain.getValue()) {
                caInfoDto.getAlternateCertificateChains().remove(altChain.getKey());
                alternateChainRoots.remove(altChain.getKey());
            }
        }
    }
    
    public String getDownloadCertLink(){
        return getEjbcaWebBean().getBaseUrl() + getEjbcaWebBean().getGlobalConfiguration().getCaPath() + "/cacert";
    }

    /**
     * Receives a request (in editcas page) and navigates to managecas.xhtml page
     * @return Navigation
     */
    public String receiveResponse() {       
        try {
            final byte[] fileBuffer = IOUtils.toByteArray(fileRecieveFileRecieveRequest.getInputStream(), fileRecieveFileRecieveRequest.getSize());
            if(isCaTypeCits()) {
                if(!fileRecieveFileRecieveRequest.getName().endsWith(".oer")) {
                    throw new EjbcaException("CITS certificate needs to be OER encoded.");
                }
                caAdminSession.receiveCitsResponse(administrator, caid, fileBuffer); 
            } else {
                String nextKeyAlias = certSignKeyRequestValue;
                if (StringUtils.isEmpty(certSignKeyRequestValue)) {
                    nextKeyAlias = null;
                }
                receiveResponse(caid, fileBuffer, nextKeyAlias, checkBoxFutureRollOver);
                try {
                    rolloverNotBefore = caBean.getRolloverNotBefore(caid);
                    rolloverNotAfter = caBean.getRolloverNotAfter(caid);
                    caCertNotAfter = caBean.getCANotAfter(caid);
                } catch (CADoesntExistsException | AuthorizationDeniedException e) {
                    log.warn("Failed to get CA notAfter and/or rollover date", e);
                }
                if (isUploadAsAlternateChain()) {
                    addInfoMessage(getEjbcaWebBean().getText("CACROSSCHAINIMPORTED"));
                } else if (rolloverNotBefore != null) {
                    addInfoMessage(getEjbcaWebBean().getText("CAROLLOVERPENDING") + getEjbcaWebBean().formatAsISO8601(rolloverNotBefore));
                } else {
                    addInfoMessage(getEjbcaWebBean().getText("CAACTIVATED"));
                }
            }
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (final Exception e) {
            log.debug("Error occurred while receiving response", e);
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }
    
    private void receiveResponse(int caid, byte[] certBytes, String nextSignKeyAlias, boolean futureRollover) throws 
    IllegalArgumentException, CertificateParsingException, CesecoreException, EjbcaException, AuthorizationDeniedException, CertPathValidatorException {
        try {
            if (certBytes == null || certBytes.length == 0) {
                throw new IllegalArgumentException("No certificate file input.");
            }
            final List<Certificate> certChain = new ArrayList<>();
            try {
                certChain.addAll(CertTools.getCertsFromPEM(new ByteArrayInputStream(certBytes), Certificate.class));
            } catch (CertificateException e) {
                log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
                // See if it is a single binary certificate
                certChain.add(CertTools.getCertfromByteArray(certBytes, Certificate.class));
            }
            if (certChain.size()==0) {
                throw new IllegalArgumentException("No certificate(s) could be read.");
            }
            if (isUploadAsAlternateChain()) {
                caAdminSession.updateCrossCaCertificateChain(administrator, cainfo, certChain);
                return;
            }
            Certificate caCertificate = certChain.get(0);
            final X509ResponseMessage resmes = new X509ResponseMessage();
            resmes.setCertificate(caCertificate);
            caAdminSession.receiveResponse(administrator, caid, resmes, certChain.subList(1, certChain.size()), nextSignKeyAlias, futureRollover);
        } catch (IllegalArgumentException | CertificateParsingException e) {
            log.debug("Error receiving response, invalid input: " + e.getMessage());
            throw e;
        } catch (CesecoreException | EjbcaException | CertPathValidatorException | AuthorizationDeniedException e) {
            // log the error here, since otherwise it may be hidden by web pages...
            log.info("Error receiving response: ", e);
            throw e;
        }
    }

    /**
     * Imports CA certificate and navigates back to the manage CA page with results.
     * @return Navigation
     */
    public String importCACertUpdate() {
        try {
            final byte[] fileBuffer = IOUtils.toByteArray(fileRecieveFileImportRenewal.getInputStream(), fileRecieveFileImportRenewal.getSize());

            if (fileBuffer == null) {
                addNonTranslatedErrorMessage("No file selected or upload failed");
                return "";
            }

            if (isCaTypeCits()) {
                addNonTranslatedErrorMessage("CITS CA updating imported certificate is not supported yet.");
                return EditCaUtil.MANAGE_CA_NAV;
            }
            importCACertUpdate(caid, fileBuffer, fileRecieveFileImportRenewal.getSubmittedFileName());
            addInfoMessage(getEjbcaWebBean().getText("CARENEWED"));
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }
    
    private void importCACertUpdate(int caId, byte[] certbytes, String fileName) throws CertificateParsingException,
            AuthorizationDeniedException, CertificateImportException, CmsCertificatePathMissingException {
        Collection<Certificate> certs;
        try {
            certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes), Certificate.class);
        } catch (CertificateException e) {
            log.debug("Input stream is not PEM certificate(s): " + e.getMessage());
            // See if it is a single binary certificate
            Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
            if (cert == null) {
                throw new CertificateParsingException(fileName + " does not contain a certificate to import");
            }
            certs = new ArrayList<>();
            certs.add(cert);
        }
        if (certs.isEmpty()) {
            throw new CertificateImportException("No certificates to import found in " + fileName);
        }
        caAdminSession.updateCACertificate(administrator, caId, EJBTools.wrapCertCollection(certs));
    }

    /**
     * Exports the current ca crypto token if allowed be the configuration.
     */
    public void exportCA() {
        try {
            FacesContext ctx = FacesContext.getCurrentInstance();
            ExternalContext ectx = ctx.getExternalContext();
            HttpServletRequest request = (HttpServletRequest) ectx.getRequest();

            //Try the password before moving on in order to verify
            CAToken caToken = caSession.getCAInfoInternal(getCaid()).getCAToken();
            final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(caToken.getCryptoTokenId());
            try {
                PrivateKey privKey = cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
                if(!ALLOWED_KEK_TYPES.contains(privKey.getAlgorithm())) {
                    log.error("Key encryption key of type: " + privKey.getAlgorithm() + " is not supported.");
                    addNonTranslatedErrorMessage(INVALID_KEK_ERROR_MESSAGE);
                    return;
                }
            } catch (CryptoTokenOfflineException e) {
                addNonTranslatedErrorMessage(e.getLocalizedMessage());
                return;
            }
            try {
                 ((SoftCryptoToken) cryptoToken).checkPasswordBeforeExport(request.getParameter(getTextFieldExportCaPassword()).toCharArray());
            } catch (CryptoTokenAuthenticationFailedException | CryptoTokenOfflineException | PrivateKeyNotExtractableException e) {
                addNonTranslatedErrorMessage(e.getLocalizedMessage());
                return;
            }
            
            HttpServletResponse response = (HttpServletResponse) ectx.getResponse();
            RequestDispatcher dispatcher = request.getRequestDispatcher(EditCaUtil.CA_EXPORT_PATH);
            request.setAttribute(REQUEST.AUTHENTICATION_TOKEN, getAdmin());
            dispatcher.forward(request, response);
            ctx.responseComplete();
        } catch (ServletException | IOException ex) {
            log.info("Error happened while trying to forward the request to ca export servlet!", ex);
        }

    }

    /**
     * Small utility function to return the current ca name used in export ca part of edit ca page.
     */
    public String getCaName() {
        return cainfo.getName();
    }

    /**
     * Returns the text field name of the export ca password field.
     */
    public String getTextFieldExportCaPassword() {
        return EditCaUtil.TEXTFIELD_EXPORTCA_PASSWORD;
    }

    /**
     * Returns the hidden ca name used in export ca function in edit ca page.
     */
    public String getHiddenCaName() {
        return EditCaUtil.HIDDEN_CANAME;
    }

    // ======================================= Helpers ===================================================================//

    private String makeRequestEditCa() {
        CAInfo caInfo = null;
        try {
            caInfo = getCaInfo();
        } catch (NumberFormatException | AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
        if (caInfo==null) {
            return "";
        }
       

        byte[] certreq = null;
        try {
            byte[] fileBuffer = null;
            if (fileRecieveFileMakeRequest != null) {
                fileBuffer = IOUtils.toByteArray(fileRecieveFileMakeRequest.getInputStream(), fileRecieveFileMakeRequest.getSize());
            }
            if (isCaTypeCits()) {
                if(getCitsHexCertificateHash().equals(CERTIFICATE_UNAVAILABLE)) {
                    // same as initial CSR
                    certreq = caAdminSession.makeCitsRequest(administrator, caid, fileBuffer, 
                            getCurrentCaCryptoTokenCertSignKey(), getCurrentCaCryptoTokenCertSignKey(), 
                            getCurrentCaCryptoTokenDefaultKey());
                } else {
                    certreq = caAdminSession.makeCitsRequest(administrator, caid, fileBuffer, 
                                                    getCurrentCaCryptoTokenCertSignKey(), null, null);
                }
            } else {
                certreq = caAdminSession.makeRequest(administrator, caid, fileBuffer, this.certExtrSignKeyReNewValue);
            }
        } catch (CADoesntExistsException | CryptoTokenOfflineException | AuthorizationDeniedException | IOException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
        caBean.saveRequestData(certreq);

        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caname", editCaName);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("caType", caInfo.getCAType());
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put("filemode", EditCaUtil.CERTREQGENMODE);
        FacesContext.getCurrentInstance().getExternalContext().getRequestMap().put(SESSION.CA_INTERFACE_BEAN, caBean);

        return EditCaUtil.DISPLAY_RESULT_NAV;
    }

    private String saveCaInternal(final CAInfo cainfo) {
        try {
            caAdminSession.editCA(getAdmin(), cainfo);
            return EditCaUtil.MANAGE_CA_NAV;
        } catch (AuthorizationDeniedException | CmsCertificatePathMissingException | InternalKeyBindingNonceConflictException | CaMsCompatibilityIrreversibleException e) {
            addNonTranslatedErrorMessage(e);
            return "";
        }
    }

    private CAInfo getCaInfo() throws NumberFormatException, AuthorizationDeniedException {
        if (caInfoDto.getCaType() == CAInfo.CATYPE_PROXY) {
            return caInfoDto.buildProxyCaInfo();
        }

        CAInfo cainfo;

        //External CAs do not require a validity to be set
        if (caInfoDto.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA && !isCaTypeCits()) {
            caInfoDto.setCaEncodedValidity(null);
        }
        
        if(isCaTypeCits()) {
            // only applicable to externally signed ca
            try {
                ItsGeographicElement geoElement = 
                        EditCaUtil.getGeographicRegion(currentGeographicRegionType, geographicElementsInGui);
                if(geoElement!=null) {
                    caInfoDto.setRegion(geoElement.toStringFormat());
                } else {
                    caInfoDto.setRegion("");
                }
            } catch (final Exception e) {
                addNonTranslatedErrorMessage(e);
                return null;
            }
        }

        try {
            cainfo = caBean.createCaInfo(caInfoDto, caid, getSubjectDn(), getApprovals(),
                    getAvailablePublisherValues(), getAvailableKeyValidatorValues());
        } catch (final Exception e) {
            addNonTranslatedErrorMessage(e);
            return null;
        }

        if (caSession.getCAInfo(getAdmin(), caid).getStatus() == CAConstants.CA_UNINITIALIZED) {
            // Allow changing of subjectDN etc. for uninitialized CAs
            cainfo.setSubjectDN(getSubjectDn());

            // We can only update the CAToken properties if we have selected a valid cryptotoken
            if (!StringUtils.isEmpty(caInfoDto.getCryptoTokenIdParam())) {
                final int cryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());

                final Properties caTokenProperties = new Properties();
                caTokenProperties.putAll(cainfo.getCAToken().getProperties());
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, caInfoDto.getCryptoTokenDefaultKey());
                if (caInfoDto.getCryptoTokenCertSignKey().length() > 0) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
                }
                if(StringUtils.isNotEmpty(caInfoDto.getCryptoTokenAlternativeCertSignKey())) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_ALTERNATIVE_CERTSIGN_STRING, caInfoDto.getCryptoTokenAlternativeCertSignKey());
                }
                
                if (caInfoDto.getSelectedKeyEncryptKey().length() > 0) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, caInfoDto.getSelectedKeyEncryptKey());
                }
                if (caInfoDto.getTestKey().length() > 0) {
                    caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, caInfoDto.getTestKey());
                }

                final CAToken newCAToken = new CAToken(cryptoTokenId, caTokenProperties);
                newCAToken.setSignatureAlgorithm(caInfoDto.getSignatureAlgorithmParam());
                newCAToken.setEncryptionAlgorithm(cainfo.getCAToken().getEncryptionAlgorithm());
                newCAToken.setKeySequence(cainfo.getCAToken().getKeySequence());
                newCAToken.setKeySequenceFormat(cainfo.getCAToken().getKeySequenceFormat());
                newCAToken.setAlternativeSignatureAlgorithm(caInfoDto.getAlternativeSignatureAlgorithmParam());
                cainfo.setCAToken(newCAToken);
            }

            final int certprofileid = caInfoDto.getCurrentCertProfileAsInteger();
            if (caInfoDto.getSignedBy() == caid) {
                caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
            }
            cainfo.setCertificateProfileId(certprofileid);
            cainfo.setDefaultCertificateProfileId(caInfoDto.getDefaultCertProfileId());
            cainfo.setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData());
            cainfo.setSignedBy(caInfoDto.getSignedBy());

            List<CertificatePolicy> policies = null;
            if (cainfo instanceof X509CAInfo) {
                policies = caBean.parsePolicies(caInfoDto.getPolicyId());
            }

            List<ExtendedCAServiceInfo> extendedCaServices;
            if (cainfo instanceof X509CAInfo) {
                final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
                extendedCaServices = caBean.makeExtendedServicesInfos();
                x509cainfo.setExtendedCAServiceInfos(extendedCaServices);
                x509cainfo.setSubjectAltName(caInfoDto.getCaSubjectAltName());
                x509cainfo.setPolicies(policies);
            }
        }
        return cainfo;
    }

    // ===================================================== Edit CA Actions ============================================= //


    // ===================================================== Other helpers   ============================================= //

    private Map<ApprovalRequestType, Integer> getApprovals() {
        final Map<ApprovalRequestType, Integer> approvals = new LinkedHashMap<>();
        if (approvalRequestItems != null && !approvalRequestItems.isEmpty()) {
            for (final ApprovalRequestItem approvalRequestItem : approvalRequestItems) {
                approvals.put(approvalRequestItem.getRequestType(), approvalRequestItem.getApprovalProfileId());
            }
        }
        return approvals;
    }

    private String getAvailablePublisherValues() {
        String availablePublisherValues = null;
        if (usedCrlPublishers != null && !usedCrlPublishers.isEmpty()) {
            availablePublisherValues = StringUtils.join(this.usedCrlPublishers.toArray(), ";");
        }
        return availablePublisherValues;
    }

    private String getAvailableKeyValidatorValues() {
        String availableKeyValidatorValues = null;
        if (usedValidators != null && !usedValidators.isEmpty()) {
            availableKeyValidatorValues = StringUtils.join(usedValidators.toArray(), ";");
       }
        return availableKeyValidatorValues;
    }

    private String getSubjectDn() {
        return caInfoDto.getCaSubjectDN();
    }

    private boolean isViewOnly() {
        boolean onlyView = false;
        if (getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                || getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource())) {
            onlyView = !getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAEDIT.resource())
                    && getEjbcaWebBean().isAuthorizedNoLogSilent(StandardRules.CAVIEW.resource());
        }
        return onlyView;
    }

    private void initCreateCaPage() {
        // Defaults in the create CA page
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam())) {
            caInfoDto.setSignatureAlgorithmParam(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        }
        if (isCaexternal) {
            caInfoDto.setDescription(cainfo.getDescription());
        }

        if (isCryptoTokenIdParamNotNull() && caInfoDto.getCryptoTokenIdParam().length() > 0 && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0) {
            currentCryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        }

        caInfoDto.setCaSubjectDN("CN=" + caInfoDto.getCaName());


        if (isCaUninitialized && caInfoDto.isCaTypeX509()) {
            String policies = "";
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            final List<CertificatePolicy> list = x509cainfo.getPolicies();
            final CertificatePolicy cp = (list != null && !list.isEmpty()) ? list.get(0) : null;
            if (cp != null) {
                policies += cp.getPolicyID();
                if (cp.getQualifier() != null) {
                    policies += " "+cp.getQualifier();
                }
            }
            caInfoDto.setPolicyId(policies);
            caInfoDto.setCaSubjectAltName(x509cainfo.getSubjectAltName());
        }

        if (caInfoDto.isCaTypeX509()) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if(x509cainfo != null) {
                final List<String> uris = x509cainfo.getAuthorityInformationAccess();
                caInfoDto.setAuthorityInformationAccess(null != uris ? StringUtils.join(uris, ";") : "");
            }
        }

        if (isCaexternal) {
            caInfoDto.setCrlCaCrlPeriod(SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaIssueInterval(SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaOverlapTime(SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaDeltaCrlPeriod(SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
        } else {
            caInfoDto.setCrlCaCrlPeriod("1" + SimpleTime.TYPE_DAYS);
            caInfoDto.setCrlCaIssueInterval("0" + SimpleTime.TYPE_MINUTES);
            caInfoDto.setCrlCaOverlapTime("10" + SimpleTime.TYPE_MINUTES);
            caInfoDto.setCrlCaDeltaCrlPeriod("0" + SimpleTime.TYPE_MINUTES);
        }

        caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
        caInfoDto.setCaSerialNumberOctetSize(String.valueOf(CesecoreConfiguration.getSerialNumberOctetSizeForNewCa()));
        usedValidators = new ArrayList<>();

        updateAvailableCryptoTokenList();
        updateAvailableSigningAlgorithmList();
    }

    private void initEditCaPage() {
        signbyexternal = cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA;
        isCaexternal = cainfo.getStatus() == CAConstants.CA_EXTERNAL;
        
        if (cainfo.getCAType() == CAInfo.CATYPE_PROXY) {
            caInfoDto.setCaType(CAInfo.CATYPE_PROXY);
            cainfo.setCAId(cainfo.getCAId());
            caInfoDto.setCaName(cainfo.getName());
            caInfoDto.setCaSubjectDN(cainfo.getSubjectDN());
            usedValidators = cainfo.getValidators();
            ProxyCaInfo proxyCaInfo = (ProxyCaInfo)cainfo;
            caInfoDto.setUpstreamUrl(proxyCaInfo.getEnrollWithCsrUrl());
            List<MutableTriple<Boolean, String, String>> headerTriples = proxyCaInfo.getHeaders().stream().map(pair -> new MutableTriple<Boolean, String, String>(false, pair.getLeft(), pair.getRight())).collect(Collectors.toList());
            caInfoDto.setHeaders(headerTriples);
            caInfoDto.setUsername(proxyCaInfo.getUsername());
            caInfoDto.setPassword(proxyCaInfo.getPassword());
            caInfoDto.setUpstreamCa(proxyCaInfo.getUpstreamCertificateAuthority());
            caInfoDto.setSansJson(proxyCaInfo.getSans());

            return;
        }

        catoken = cainfo.getCAToken();
        keyValidatorMap = keyValidatorSession.getKeyValidatorIdToNameMap(cainfo.getCAType());
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam())) {
            caInfoDto.setSignatureAlgorithmParam(catoken.getSignatureAlgorithm());
        }
        if (StringUtils.isEmpty(caInfoDto.getAlternativeSignatureAlgorithmParam())) {
            caInfoDto.setAlternativeSignatureAlgorithmParam(catoken.getAlternativeSignatureAlgorithm());
        }
        isCaRevoked = cainfo.getStatus() == CAConstants.CA_REVOKED || RevokedCertInfo.isRevoked(cainfo.getRevocationReason());
        revokable = cainfo.getStatus() != CAConstants.CA_REVOKED && cainfo.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE
                && cainfo.getStatus() != CAConstants.CA_EXTERNAL && !RevokedCertInfo.isPermanentlyRevoked(cainfo.getRevocationReason());
        waitingresponse = cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE;
        isCaUninitialized = cainfo.getStatus() == CAConstants.CA_UNINITIALIZED;
        caInfoDto.setCaType(cainfo.getCAType());
        caInfoDto.setKeySequenceFormat(cainfo.getCAToken().getKeySequenceFormat());
        caInfoDto.setDescription(cainfo.getDescription());
        caInfoDto.setDoEnforceUniquePublickeys(cainfo.isDoEnforceUniquePublicKeys());
        caInfoDto.setDoEnforceKeyRenewal(cainfo.isDoEnforceKeyRenewal());
        caInfoDto.setDoEnforceUniqueDN(cainfo.isDoEnforceUniqueDistinguishedName());
        caInfoDto.setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        caInfoDto.setUseCertificateStorage(cainfo.isUseCertificateStorage());
        caInfoDto.setAcceptRevocationsNonExistingEntry(cainfo.isAcceptRevocationNonExistingEntry());
        caInfoDto.setDefaultCertificateProfile(String.valueOf(cainfo.getDefaultCertificateProfileId()));
        caInfoDto.setUseNoConflictCertificateData(cainfo.isUseNoConflictCertificateData());

        if (isCaUninitialized) {
            caInfoDto.setCurrentCertProfile(String.valueOf(cainfo.getCertificateProfileId()));
        } else {
            if (cainfo.getCertificateProfileId() != 0) {
                caInfoDto.setCurrentCertProfile(certificateProfileSession.getCertificateProfileName(cainfo.getCertificateProfileId()));
            } else {
                caInfoDto.setCurrentCertProfile(getEjbcaWebBean().getText("NOTUSED"));
            }
        }

        currentCryptoTokenId = catoken.getCryptoTokenId();
        caInfoDto.setCryptoTokenIdParam(String.valueOf(catoken.getCryptoTokenId()));

        if (cainfo.getSignedBy() >= 0 && cainfo.getSignedBy() <= CAInfo.SPECIALCAIDBORDER) {
            if (cainfo.getSignedBy() == CAInfo.SELFSIGNED) {
                caInfoDto.setSignedBy(CAInfo.SELFSIGNED);
            }
            if (cainfo.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
                caInfoDto.setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
            }
        } else {
            caInfoDto.setSignedBy(cainfo.getSignedBy());
        }

        caInfoDto.setCaEncodedValidity(cainfo.getEncodedValidity());
        final boolean validityNotUsed = ((isCaexternal && !isCaTypeCits()) || (!isCaUninitialized && signbyexternal));
        if (validityNotUsed && (StringUtils.isBlank(caInfoDto.getCaEncodedValidity()) || "0d".equals(caInfoDto.getCaEncodedValidity()))) {
            hideValidity = true;
            caInfoDto.setCaEncodedValidity("");
        }

        caInfoDto.setUseCertReqHistory(cainfo.isUseCertReqHistory());
        caInfoDto.setUseUserStorage(cainfo.isUseUserStorage());
        
        if (caInfoDto.isCaTypeCits() && cainfo != null) {
            caInfoDto.setCertificateId(((CitsCaInfo)cainfo).getCertificateId());
            ItsGeographicRegion region = ((CitsCaInfo)cainfo).getRegion();
            geographicElementsInGui = new ArrayList<>();
            if(region!=null) {
                EditCaUtil.loadGeographicRegionsForGui(geographicElementsInGui, region);
                caInfoDto.setRegion(region.toString());
                currentGeographicRegionType = geographicElementsInGui.get(0).getType();
            } else {
                caInfoDto.setRegion("");
            }
        }

        if (caInfoDto.isCaTypeSsh() && cainfo != null) {
            final SshCaInfo sshCaInfo = (SshCaInfo) cainfo;
            caInfoDto.setUseLdapDNOrder(sshCaInfo.getUseLdapDnOrder());
        }

        if (caInfoDto.isCaTypeX509() && cainfo != null) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            caInfoDto.setDefaultCRLDistPoint(x509cainfo.getDefaultCRLDistPoint());
            caInfoDto.setDefaultCRLIssuer(x509cainfo.getDefaultCRLIssuer());
            caInfoDto.setCaDefinedFreshestCRL(x509cainfo.getCADefinedFreshestCRL());
            caInfoDto.setDefaultOCSPServiceLocator(x509cainfo.getDefaultOCSPServiceLocator());
            caInfoDto.setCaSerialNumberOctetSize(String.valueOf(x509cainfo.getCaSerialNumberOctetSize()));
            caInfoDto.setDoPreProduceOcspResponses(x509cainfo.isDoPreProduceOcspResponses());
            caInfoDto.setDoPreProduceOcspResponseUponIssuanceAndRevocation(x509cainfo.isDoPreProduceOcspResponseUponIssuanceAndRevocation());
            caInfoDto.setDoStoreOcspResponsesOnDemand(x509cainfo.isDoStoreOcspResponsesOnDemand());
            caInfoDto.setMsCaCompatible(x509cainfo.isMsCaCompatible());
            Map<String, List<String>> alternateChains = new HashMap<>();
            if(x509cainfo.getAlternateCertificateChains()!=null) {
                alternateChains.putAll(x509cainfo.getAlternateCertificateChains());
            }
            caInfoDto.setAlternateCertificateChains(alternateChains);
            
            if(x509cainfo.getPolicies() == null || (x509cainfo.getPolicies().isEmpty())) {
                caInfoDto.setPolicyId(getEjbcaWebBean().getText("NONE"));
             } else {
               // Some special handling to handle the upgrade case after CertificatePolicy changed classname
               String policyId = null;
               final Object obj = x509cainfo.getPolicies().get(0);
               if (obj instanceof CertificatePolicy) {
                 policyId = ((CertificatePolicy)obj).getPolicyID();
               } else {
                 policyId = ((org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy)obj).getPolicyID();
               }
               if (policyId == null) {
                   caInfoDto.setPolicyId(getEjbcaWebBean().getText("NONE"));
               } else {
                   caInfoDto.setPolicyId(policyId);
               }
             }
            caInfoDto.setUseUtf8Policy(x509cainfo.getUseUTF8PolicyText());
            caInfoDto.setUsePrintableStringSubjectDN(x509cainfo.getUsePrintableStringSubjectDN());
            caInfoDto.setUseLdapDNOrder(x509cainfo.getUseLdapDnOrder());
            caInfoDto.setNameConstraintsExcluded(NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsExcluded()));
            caInfoDto.setNameConstraintsPermitted(NameConstraint.formatNameConstraintsList(x509cainfo.getNameConstraintsPermitted()));
            crlCaCRLDPExternal = x509cainfo.getExternalCdp();
            caInfoDto.setUseAuthorityKeyIdentifier(x509cainfo.getUseAuthorityKeyIdentifier());
            caInfoDto.setAuthorityKeyIdentifierCritical(x509cainfo.getAuthorityKeyIdentifierCritical());
            caInfoDto.setUseCrlNumber(x509cainfo.getUseCRLNumber());
            caInfoDto.setCrlNumberCritical(x509cainfo.getCRLNumberCritical());
            caInfoDto.setUseCrlDistributiOnPointOnCrl(x509cainfo.getUseCrlDistributionPointOnCrl());
            caInfoDto.setCrlDistributionPointOnCrlCritical(x509cainfo.getCrlDistributionPointOnCrlCritical());

            final List<String> urisAuthorityInformationAccess = x509cainfo.getAuthorityInformationAccess();
            final List<String> urisCertificateAiaDefaultCaIssuerUri = x509cainfo.getCertificateAiaDefaultCaIssuerUri();
            caInfoDto.setAuthorityInformationAccess(null != urisAuthorityInformationAccess ? StringUtils.join(urisAuthorityInformationAccess, ";") : "");
            caInfoDto.setCertificateAiaDefaultCaIssuerUri(null != urisCertificateAiaDefaultCaIssuerUri ? StringUtils.join(urisCertificateAiaDefaultCaIssuerUri, ";") : "");
            caInfoDto.setKeepExpiredOnCrl(x509cainfo.getKeepExpiredCertsOnCRL());
            caInfoDto.setUsePartitionedCrl(x509cainfo.getUsePartitionedCrl());
            caInfoDto.setCrlPartitions(x509cainfo.getCrlPartitions());
            caInfoDto.setSuspendedCrlPartitions(x509cainfo.getSuspendedCrlPartitions());
            caInfoDto.setCrlCaCrlPeriod(SimpleTime.getInstance(cainfo.getCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaIssueInterval(SimpleTime.getInstance(cainfo.getCRLIssueInterval()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaOverlapTime(SimpleTime.getInstance(cainfo.getCRLOverlapTime()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setCrlCaDeltaCrlPeriod(SimpleTime.getInstance(cainfo.getDeltaCRLPeriod()).toString(SimpleTime.TYPE_MINUTES));
            caInfoDto.setGenerateCrlUponRevocation(cainfo.isGenerateCrlUponRevocation());
            caInfoDto.setAllowChangingRevocationReason(cainfo.isAllowChangingRevocationReason());
            caInfoDto.setAllowInvalidityDate(cainfo.isAllowInvalidityDate());
        }

        caInfoDto.setFinishUser(cainfo.getFinishUser());

        if (caInfoDto.isCaTypeX509()) {
            caInfoDto.setSharedCmpRaSecret(((X509CAInfo) cainfo).getCmpRaAuthSecret());
        }

        if (isCaUninitialized && caInfoDto.isCaTypeX509()) {
            String policies = "";
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            final List<CertificatePolicy> list = x509cainfo.getPolicies();
            final CertificatePolicy cp = (list != null && !list.isEmpty()) ? list.get(0) : null;
            if (cp != null) {
                policies += cp.getPolicyID();
                if (cp.getQualifier() != null) {
                    policies += " "+cp.getQualifier();
                }
            }
            caInfoDto.setPolicyId(policies);
        }

        if (caInfoDto.isCaTypeX509()) {
            final X509CAInfo x509cainfo = (X509CAInfo) cainfo;
            if (!isCaUninitialized) {
                if (x509cainfo.getSubjectAltName() == null || x509cainfo.getSubjectAltName().trim().equals("")) {
                    caInfoDto.setCaSubjectAltName(getEjbcaWebBean().getText("NONE"));
                } else {
                    caInfoDto.setCaSubjectAltName(x509cainfo.getSubjectAltName());
                }
                try {
                    rolloverNotBefore = caBean.getRolloverNotBefore(caid);
                    rolloverNotAfter = caBean.getRolloverNotAfter(caid);
                    caCertNotAfter = caBean.getCANotAfter(caid);
                } catch (CADoesntExistsException | AuthorizationDeniedException e) {
                    log.warn("Failed to get CA notAfter and/or rollover date", e);
                }
            } else {
                caInfoDto.setCaSubjectAltName(x509cainfo.getSubjectAltName());
            }
            caInfoDto.setRequestPreProcessor(x509cainfo.getRequestPreProcessor());
        }

        caInfoDto.setCaSubjectDN(cainfo.getSubjectDN());
        approvalRequestItems = initApprovalRequestItems();
        final Collection<Certificate> cachain = cainfo.getCertificateChain();
        if (cachain != null && !cachain.isEmpty()) {
            final Iterator<Certificate> iter = cachain.iterator();
            final Certificate cacert = iter.next();
            issuerDn = CertTools.getIssuerDN(cacert);
        }
        usedValidators = cainfo.getValidators();

        if (isCaUninitialized) {
            createLinkCertificate = false;
        } else {
            hasLinkCertificate = (caAdminSession.getLatestLinkCertificate(caid) != null);
        }

        if (isRenderUseCaNameChange()) {
            newSubjectDn = cainfo.getSubjectDN();
        }

        if (isCaUninitialized) {
            updateAvailableCryptoTokenList();
            updateAvailableSigningAlgorithmList();
        }
    }

    private void updateAvailableSigningAlgorithmList() {
        availableSigningAlgorithmSelectItems = getAvailableSigningAlgList();
        
        // Update caInfoDTO with a default algorithm
        if (StringUtils.isEmpty(caInfoDto.getSignatureAlgorithmParam()) && availableSigningAlgorithmSelectItems.size() > 0){
            // Never suggest SHA1 based signature algorithms as default
            if (availableSigningAlgorithmSelectItems.get(0).getLabel() == AlgorithmConstants.SIGALG_SHA1_WITH_RSA) {
                caInfoDto.setSignatureAlgorithmParam(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);                
            } else if (availableSigningAlgorithmSelectItems.get(0).getLabel() == AlgorithmConstants.SIGALG_SHA1_WITH_ECDSA) {
                caInfoDto.setSignatureAlgorithmParam(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
            } else {
                caInfoDto.setSignatureAlgorithmParam(availableSigningAlgorithmSelectItems.get(0).getLabel());
            }
        }
    }
    
    private void updateAvailableCryptoTokenList() {
        updateAvailableCryptoTokenList(false);
    }

    private void updateAvailableCryptoTokenList(boolean citsCompatible) {
        // Defaults if an error occurs
        suitableCryptoTokenExists = true;
        availableCryptoTokenSelectItems = Collections.emptyList();
        try {
            List<Entry<String, String>> availableCryptoTokens = 
                            caBean.getAvailableCryptoTokens(isEditCA, citsCompatible);
            if (availableCryptoTokens == null) {
                availableCryptoTokens = Collections.emptyList();
            }
            suitableCryptoTokenExists = !availableCryptoTokens.isEmpty();

            final List<SelectItem> resultList = new ArrayList<>();
            int numSelected = 0; // should be 1 after the loop

            for (final Entry<String, String> entry : availableCryptoTokens) {
                // Ensure that we have a default for the next section
                if (isCryptoTokenIdParamNull() || caInfoDto.getCryptoTokenIdParam().isEmpty()) {
                    caInfoDto.setCryptoTokenIdParam(entry.getKey());
                }

                final boolean selectCurrent = entry.getKey().equals(caInfoDto.getCryptoTokenIdParam());
                numSelected += selectCurrent ? 1 : 0;
                if (currentCryptoTokenId == 0 || selectCurrent) {
                    currentCryptoTokenId = Integer.parseInt(entry.getKey());
                }
                final boolean itemSelectionDisabled = currentCryptoTokenId == CAInterfaceBean.PLACEHOLDER_CRYPTO_TOKEN_ID;
                resultList.add(new SelectItem(entry.getKey(), entry.getValue(), "", itemSelectionDisabled));
            }

            if (numSelected == 0) {
                resultList.add(new SelectItem(caInfoDto.getCryptoTokenIdParam(), "-" + getEjbcaWebBean().getText("CRYPTOTOKEN_MISSING_OR_EMPTY") + " "
                        + caInfoDto.getCryptoTokenIdParam() + "-"));
                caInfoDto.setCryptoTokenIdParam(null);
                currentCryptoTokenId = 0;
            }
            availableCryptoTokenSelectItems = resultList;
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while listing available CryptoTokens!", e);
        }
        failedCryptoTokenLinkMap = new HashMap<>();
        try {
            List<Entry<String, String>> failedCryptoTokens = caBean.getFailedCryptoTokens(caInfoDto.getSignatureAlgorithmParam());
            for (final Entry<String, String> entry : failedCryptoTokens) {
                failedCryptoTokenLinkMap.put(entry.getKey(), entry.getValue());
            }
        } catch (final AuthorizationDeniedException e) {
            log.error("Error while listing failed CryptoTokens!", e);
        }
    }

    private void updateCryptoTokenInfo() {
        currentCryptoTokenName = "";
        currentCryptoTokenPresent = false;
        currentCryptoTokenLink = "";
        if (currentCryptoTokenId != 0) {
            try {
                final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAdmin(), currentCryptoTokenId);
                if (cryptoTokenInfo == null) {
                    final String errMsg = "CryptoToken " + currentCryptoTokenId + " not found.";
                    log.info(errMsg);
                    currentCryptoTokenName = errMsg;
                } else {
                    currentCryptoTokenName = cryptoTokenInfo.getName();
                    currentCryptoTokenLink = CRYPTO_TOKEN_LINK + currentCryptoTokenId;
                    currentCryptoTokenPresent = cryptoTokenManagementSession.isCryptoTokenPresent(getAdmin(), currentCryptoTokenId);
                }
            } catch (final AuthorizationDeniedException e) {
                log.error("Error while getting crypto token info!", e);
            }
        }
    }

    /** Lists the key aliases from the selected crypto token, and sets defaults and updates the "in use" map. */
    private void updateKeyAliases() {
        if (isCryptoTokenIdParamNotNull() && caInfoDto.getCryptoTokenIdParam().length() > 0 && Integer.parseInt(caInfoDto.getCryptoTokenIdParam()) != 0) {
            currentCryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        }
        availableCryptoTokenKeyAliases = new ArrayList<>(); // Avoids NPE in getters if the code below fails.
        availableCryptoTokenMixedAliases = new ArrayList<>();
        availableCryptoTokenEncryptionAliases = new ArrayList<>();
        availableCryptoTokenAlternativeKeyAliases = new ArrayList<>();
        if (!isCaexternal) {
            updateCryptoTokenInfo();
            if (currentCryptoTokenId != 0) {
                try {
                    // List of key aliases is needed even on Edit CA page, to show the renew key dropdown list
                    updateAvailableKeyAliasesList();
                    generateKeyAlreadyInUseMap();
                    if (isEditCA) {
                        setKeyAliasesFromCa();
                    } else {
                        setDefaultKeyAliases();
                    }
                } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                    log.error("Error while listing crypto token key aliases!", e);
                }
            }
        }
    }

    private void updateAvailableKeyAliasesList() throws CryptoTokenOfflineException, AuthorizationDeniedException {
        final List<KeyPairInfo> keyPairInfos = caBean.getKeyPairInfos(currentCryptoTokenId);
        availableCryptoTokenKeyAliases = caBean.getAvailableCryptoTokenAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        availableCryptoTokenMixedAliases = caBean.getAvailableCryptoTokenMixedAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        availableCryptoTokenEncryptionAliases = caBean.getAvailableCryptoTokenEncryptionAliases(keyPairInfos, caInfoDto.getSignatureAlgorithmParam());
        if (StringUtils.isNotEmpty(caInfoDto.getAlternativeSignatureAlgorithmParam())) {
            availableCryptoTokenAlternativeKeyAliases = caBean.getAvailableCryptoTokenAliases(keyPairInfos,
                    caInfoDto.getAlternativeSignatureAlgorithmParam());
        }
    }

    private void generateKeyAlreadyInUseMap() {
        // Create already in use key map
        for (final String alias : availableCryptoTokenMixedAliases) {
            final String alreadyInUse = isKeyInUse(caSession.getAuthorizedCaIds(getAdmin()), alias, currentCryptoTokenId) ? " (Already in use)"
                    : StringUtils.EMPTY;
            aliasUsedMap.put(alias, alreadyInUse);
        }
        for(final String alias : availableCryptoTokenAlternativeKeyAliases) {
            final String alreadyInUse = isKeyInUse(caSession.getAuthorizedCaIds(getAdmin()), alias, currentCryptoTokenId) ? " (Already in use)"
                    : StringUtils.EMPTY;
            aliasUsedMap.put(alias, alreadyInUse);
        }
    }
    
    /**
     * Checks if keys in current crypto token are already in use by another CA or not
     * This method used while creating a new CA to warn users about keys which are already in use
     * by other CAs.
     *
     * @param CAIds CA ids.
     * @param alias alias.
     * @param currentCryptoTokenId crypto token id.
     * @return boolean true if crypto key is used by another CA or false otherwise.
     * @throws IllegalStateException illegal state exception.
     */
    private boolean isKeyInUse(final Collection<Integer> CAIds, final String alias, final int currentCryptoTokenId) {
        for (final int caId : CAIds) {
            final CAInfo caInfo = caSession.getCAInfoInternal(caId);
            if (caInfo != null && caInfo.getCAToken()!= null && 
                    currentCryptoTokenId == caInfo.getCAToken().getCryptoTokenId() && caInfo.getCAToken().getProperties().contains(alias)) {
                return true;
            }
        }
        return false;
    }

    private void initPageVariables(final Map<String, Object> requestMap) {
        // Make sure we have required parameters available in request map
        if (requestMap != null && requestMap.get("iseditca") instanceof Boolean) {
            isEditCA = (Boolean) requestMap.get("iseditca");
            if (isEditCA) {
                editCaName = (String) requestMap.get("editcaname");
                caid = (Integer) requestMap.get("caid");
            } else {
                caInfoDto.setCaName((String) requestMap.get("createcaname"));
            }
        } else { // This page is accessed not via manage ca page we should not continue!
            try {
                FacesContext.getCurrentInstance().getExternalContext().redirect(EditCaUtil.MANAGE_CA_NAV + ".xhtml");
            } catch (final IOException e) {
                throw new FacesException("Cannot redirect to " + EditCaUtil.MANAGE_CA_NAV + " due to IO exception.", e);
            }
        }
    }

    private List<ApprovalRequestItem> initApprovalRequestItems() {
        final List<ApprovalRequestItem> approvalRequestItems = new ArrayList<>();
        if (cainfo != null && cainfo.getApprovals() != null) {
            final LinkedHashMap<ApprovalRequestType, Integer> approvals = (LinkedHashMap<ApprovalRequestType, Integer>) cainfo.getApprovals();
            for (final ApprovalRequestType approvalRequestType : ApprovalRequestType.values()) {
                // Hide ACME approval types.
                if (ApprovalRequestType.ACMEACCOUNTREGISTRATION.equals(approvalRequestType) 
                 || ApprovalRequestType.ACMEACCOUNTKEYCHANGE.equals(approvalRequestType)) {
                    continue;
                }
                approvalRequestItems.add(new ApprovalRequestItem(approvalRequestType, approvals.getOrDefault(approvalRequestType, -1)));
            }
        }
        return approvalRequestItems;
    }

    public void addBlankHeader() {
        if (caInfoDto.getHeaders() == null) {
            caInfoDto.setHeaders(new ArrayList<>());
        }
        caInfoDto.getHeaders().add(new MutableTriple<>(false, "", ""));
    }

    public void removeHeader() {
        caInfoDto.getHeaders().removeIf(triple -> triple.left);
    }

    public boolean getHasAnyHeader() {
        return caInfoDto.getHeaders().size() > 0;
    }
    
    public String getUpstreamPassword() {
        // can never see the pasword
        return HIDDEN_KF_ENROLL_CA_UPSTREAM_PASSWORD;
    }
    
    public void setUpstreamPassword(String newPassword) {
        if(!newPassword.equals(HIDDEN_KF_ENROLL_CA_UPSTREAM_PASSWORD)) {
            caInfoDto.setPassword(newPassword);
        }
    }
    
}
