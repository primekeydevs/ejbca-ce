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
package org.ejbca.ui.web.admin;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

import jakarta.ejb.EJB;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;
import java.io.Serializable;

/**
 * Backing bean for the menu on the left (in the default theme) in the AdminWeb.
 * @version $Id$
 */
@RequestScoped
@Named
public class AdminMenuBean extends BaseManagedBean implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    private GlobalConfiguration getGlobalConfiguration() {
        return (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    /*===CA FUNCTIONS===*/
    
    public boolean isAuthorizedToViewCA() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CAVIEW.resource());
    }
    
    public boolean isAuthorizedToViewCAActivation() {
        return getEjbcaWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CAVIEW.resource());
    }
    
    public boolean isAuthorizedToViewCertificateProfile() {
        return getEjbcaWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CERTIFICATEPROFILEVIEW.resource());
    }
    
    public boolean isAuthorizedToViewCryptotoken() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), CryptoTokenRules.VIEW.resource());
    }
    
    public boolean isAuthorizedToViewPublishers() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWPUBLISHER);
    }
    
    public boolean isAuthorizedToViewValidators() {
        return getEjbcaWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWVALIDATOR);
    }
    
    public boolean isAuthorizedToViewCAHeader() {
        return isAuthorizedToViewCA()
                || isAuthorizedToViewCAActivation()
                || isAuthorizedToViewCertificateProfile()
                || isAuthorizedToViewCryptotoken()
                || isAuthorizedToViewPublishers()
                || isAuthorizedToViewValidators();
    }
       
    /*===RA FUNCTIONS===*/
    
    public boolean isAuthorizedToCreateEndEntity() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_CREATEENDENTITY);
    }
    
    public boolean isAuthorizedToViewEndEntityProfiles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITYPROFILES);
    }
    
    public boolean isAuthorizedToViewEndEntity() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_VIEWENDENTITY);
    }
    
    public boolean isAuthorizedToEditUserDataSources() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_EDITUSERDATASOURCES);
    }
    
    public boolean isAuthorizedToViewRAHeader() {
        return getEjbcaErrorWebBean().isRunningBuildWithCA()
                && (isAuthorizedToCreateEndEntity()
                || isAuthorizedToViewEndEntityProfiles()
                || isAuthorizedToViewEndEntity()
                || isAuthorizedToEditUserDataSources());
    }
    
    /*===VA FUNCTIONS===*/
    
    public boolean isAuthorizedToViewVAHeader() {
        return getEjbcaErrorWebBean().isRunningBuildWithVA()
                && isAuthorizedViewInternalKeyBindings();
    }
    
    /*===CONTROLS===*/
    
    public boolean isAuthorizedToViewRoles() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.VIEWROLES.resource());
    }
    
    public boolean isAuthorizedToViewApprovalProfiles() {
        return getEjbcaErrorWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.APPROVALPROFILEVIEW.resource());
    }
    
    public boolean isAuthorizedToApproveActions() {
        return getEjbcaErrorWebBean().isRunningBuildWithCA()
                && (authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_APPROVEENDENTITY) 
                || authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_APPROVECAACTION));
    }
    
    public boolean isAuthorizedToViewLog() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AuditLogRules.VIEW.resource()) &&
                !getEjbcaWebBean().getEjb().getSecurityEventsAuditorSession().getQuerySupportingLogDevices().isEmpty();
    }
    
    public boolean isAuthorizedToViewControlsHeader() {
        return isAuthorizedToViewRoles()
                || isAuthorizedToViewApprovalProfiles()
                || isAuthorizedToApproveActions()
                || isAuthorizedToViewLog();
    }
    
    /*===PROTOCOLS===*/
    
    public boolean isAuthorizedToViewAcmeConfiguration() {
        return getEjbcaWebBean().isRunningEnterprise() 
                && getEjbcaErrorWebBean().isRunningBuildWithCA()
                && isAuthorizedToViewSystemConfiguration();
    }
    
    public boolean isAuthorizedToViewAutoenrollConfiguration() {
        return getEjbcaWebBean().isRunningEnterprise()
                && (getEjbcaErrorWebBean().isRunningBuildWithCA() || getEjbcaErrorWebBean().isRunningBuildWithRA())
                && isAuthorizedToViewSystemConfiguration();
    }
    
    public boolean isAuthorizedToViewCmpConfiguration() {
        return getEjbcaErrorWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }
    
    public boolean isAuthorizedToViewEstConfiguration() {
        return getEjbcaWebBean().isRunningEnterprise() 
                && getEjbcaErrorWebBean().isRunningBuildWithCA()
                && isAuthorizedToViewSystemConfiguration();
    }
    
    public boolean isAuthorizedToViewScepConfiguration() {
        return getEjbcaErrorWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }
    
    public boolean isAuthorizedToViewProtocolsHeader() {
        return isAuthorizedToViewAcmeConfiguration()
                || isAuthorizedToViewAutoenrollConfiguration()
                || isAuthorizedToViewCmpConfiguration()
                || isAuthorizedToViewEstConfiguration()
                || isAuthorizedToViewScepConfiguration();
    }
    
    /*===CONFIGURATION===*/
    
    public boolean isAuthorizedToViewSystemConfiguration() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
    }
    
    public boolean isAuthorizedViewInternalKeyBindings() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), InternalKeyBindingRules.VIEW.resource());
    }
    
    public boolean isAuthorizedToViewPeerConnectors() {
        return getEjbcaWebBean().isPeerConnectorPresent() && authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.REGULAR_PEERCONNECTOR_VIEW);
    }
    
    public boolean isAuthorizedToViewServices() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.SERVICES_VIEW);
    }
    
    public boolean isAuthorizedToConfigureSystem() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource()) 
                || authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource()) 
                || authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource());
    }
    
    public boolean isUpgradeRequired() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().isPostUpgradeRequired();
    }
    
    public boolean isAuthorizedToEditPreferences() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), AccessRulesConstants.ROLE_ADMINISTRATOR);
    }
    
    public boolean isAuthorizedToViewConfigurationHeader() {
        return isAuthorizedToViewSystemConfiguration()
                || isAuthorizedViewInternalKeyBindings()
                || isAuthorizedToViewPeerConnectors()
                || isAuthorizedToViewServices()
                || isAuthorizedToConfigureSystem()
                || isUpgradeRequired();
    }
    
    /*===OTHER===*/
    
    public boolean isAuthorizedToViewRaWeb() {
        return getEjbcaErrorWebBean().isRunningBuildWithRAWeb();
    }
    
    public boolean isHelpEnabled() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().isHelpEnabled();
    }
    
    public boolean isLogoutAvailable() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getUseSessionTimeout();
    }
    
    public String getHeadBannerUrl() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl() + getGlobalConfiguration().getHeadBanner();
    }
    
    public boolean isNonDefaultHeadBanner() {
        return getGlobalConfiguration().isNonDefaultHeadBanner();
    }
    
    public String getAppNameCapital() {
        return InternalConfiguration.getAppNameCapital();
    }
    
    public String getLogoUrl() {
        return getEjbcaWebBean().getImagePath(getEjbcaWebBean().getEditionFolder() + "/keyfactor-"+ InternalConfiguration.getAppNameLower() +"-logo.png");
    }

    public String getFaviconUrl() {
        return getEjbcaWebBean().getImagePath(getEjbcaWebBean().getEditionFolder() + "/favicon.png");
    }

    /** 
     * @return the URL to EJBCA Admin UI, i.e. https://hostname:8443/ejbca/adminweb/, always ends with a '/'
     */
    public String getAdminWebUrl() {
        String url = getEjbcaWebBean().getBaseUrl() + getGlobalConfiguration().getAdminWebPath();
        // This most likely always ends with a / but make damn sure
        if (!StringUtils.endsWith(url, "/")) {
            url += "/";
        }
        return url;
    }
}
