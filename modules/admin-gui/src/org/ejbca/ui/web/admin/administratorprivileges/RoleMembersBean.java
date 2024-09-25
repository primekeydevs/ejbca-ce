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
package org.ejbca.ui.web.admin.administratorprivileges;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.OAuth2AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

import com.keyfactor.util.StringTools;

/**
 * Managed Bean for the Role Member manage/view page.
 * 
 */
@ViewScoped
@Named
public class RoleMembersBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RoleMembersBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    GlobalConfigurationSessionLocal globalConfigurationSession;

    private OAuthConfiguration oAuthConfiguration;

    private String roleIdParam;
    private Role role;

    private List<SelectItem> matchWithItems = null;
    private String matchWithSelected = X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE + ":" + X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue();
    private Integer tokenIssuerId;
    private Integer tokenProviderId;
    private String tokenMatchValue = "";
    private String description = "";

    private ListDataModel<RoleMember> roleMembers = null;
    private RoleMember roleMemberToDelete = null;
    
    private Map<Integer, String> caIdToNameMap = null;

    @PostConstruct
    private void postConstruct() {
        // Read HTTP param "roleId" that should be interpreted as an integer
        roleIdParam = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("roleId");
    }
    
    public RoleMembersBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.VIEWROLES.resource());
    }
    
    /** Redirect back to this page with the correct roleId for non-ajax requests */
    private void nonAjaxPostRedirectGet() {
        super.nonAjaxPostRedirectGet("?roleId="+roleIdParam);
    }
    
    /**
     * Get the appropriate Access match type based on the access match value.
     * @param accessMatchValue
     * @return Equal Case sensitive unless access match value forces something else.
     */
    private AccessMatchType getAccessMatchType(AccessMatchValue accessMatchValue) {
        if (accessMatchValue.equals(X500PrincipalAccessMatchValue.WITH_SERIALNUMBER)
                || accessMatchValue.equals(X500PrincipalAccessMatchValue.WITH_COUNTRY)
                || accessMatchValue.equals(X500PrincipalAccessMatchValue.WITH_DNEMAILADDRESS)
                || accessMatchValue.equals(X500PrincipalAccessMatchValue.WITH_STATEORPROVINCE)
                || accessMatchValue.equals(X500PrincipalAccessMatchValue.WITH_RFC822NAME)){
            return AccessMatchType.TYPE_EQUALCASEINS;
        }
        return AccessMatchType.TYPE_EQUALCASE;
    }

    /** @return true when admin is authorized to edit members of this role */
    public boolean isAuthorizedToEditRole() {
        try {
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EDITROLES.resource()) && getRole()!=null) {
                roleSession.assertAuthorizedToRoleMembers(getAdmin(), getRole().getRoleId(), true);
                return true;
            }
        } catch (AuthorizationDeniedException e) {
            // NOPMD: Ignore.. would be nicer with a API call returning a boolean
        }
        return false;
    }

    /** @return an authorized existing role based on the roleId HTTP param or null if no such role was found. */
    public Role getRole() {
        if (role==null && NumberUtils.isNumber(roleIdParam)) {
            try {
                role = roleSession.getRole(getAdmin(), Integer.parseInt(roleIdParam));
                if (role==null && log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access non-existing role.");
                }
            } catch (NumberFormatException | AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access a role: " + e.getMessage());
                }
            }
        }
        return role;
    }

    /** @return a ListDataModel of all RoleMembers in this Role (sorted) */
    public ListDataModel<RoleMember> getRoleMembers() {
        if (roleMembers==null) {
            final List<RoleMember> roleMembers = roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId());
            Collections.sort(roleMembers, new Comparator<RoleMember>() {
                @Override
                public int compare(final RoleMember roleMember1, final RoleMember roleMember2) {
                    final String matchWithItemString1 = getMatchWithItemString(roleMember1);
                    final String matchWithItemString2 = getMatchWithItemString(roleMember2);
                    final int compareA = matchWithItemString1.compareTo(matchWithItemString2);
                    if (compareA!=0) {
                        return compareA;
                    }
                    final String tokenIssuerIdString1 = getTokenIssuerIdString(roleMember1);
                    final String tokenIssuerIdString2 = getTokenIssuerIdString(roleMember2);
                    final int compareB = tokenIssuerIdString1.compareTo(tokenIssuerIdString2);
                    if (compareB!=0) {
                        return compareB;
                    }
                    return roleMember1.getTokenMatchValue().compareTo(roleMember2.getTokenMatchValue());
                }
            });
            this.roleMembers = new ListDataModel<>(roleMembers);
        }
        return roleMembers;
    }

    /** @return a viewable list of 'match with'-texts */
    @SuppressWarnings("deprecation")
    public List<SelectItem> getMatchWithItems() {
        if (matchWithItems == null) {
            matchWithItems = new ArrayList<>();
            final List<String> tokenTypes = new ArrayList<>(AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes());
            Collections.sort(tokenTypes);
            for (final String tokenType : tokenTypes) {
                // Allowing CE and Enterprise editions
                //if (tokenType.equals(OAuth2AuthenticationTokenMetaData.TOKEN_TYPE) && !getEjbcaWebBean().isRunningEnterprise()) {
                //    continue;
                //}
                final AuthenticationTokenMetaData authenticationTokenMetaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType);
                if (authenticationTokenMetaData.isUserConfigurable()) {
                    for (final AccessMatchValue accessMatchValue : authenticationTokenMetaData.getAccessMatchValues()) {
                        // Special exclusion of this rather useless match value that will never match anything
                        if (!X500PrincipalAccessMatchValue.NONE.equals(accessMatchValue)) {
                            matchWithItems.add(new SelectItem(tokenType + ":" + accessMatchValue.getNumericValue(), 
                                    getEjbcaWebBean().getText(tokenType) + ": " + getEjbcaWebBean().getText(accessMatchValue.name())));
                        }
                    }
                }
            }
        }
        return matchWithItems;
    }

    /** @return the selected tokenType and tokenMatchKey combo */
    public String getMatchWithSelected() { return matchWithSelected; }
    /** Set the selected tokenType and tokenMatchKey combo */
    public void setMatchWithSelected(final String matchWithSelected) { this.matchWithSelected = matchWithSelected; }

    /** @return a human readable version of the tokenType and tokenMatchKey values */
    public String getMatchWithItemString(final RoleMember roleMember) {
        final AuthenticationTokenMetaData authenticationTokenMetaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(roleMember.getTokenType());
        if (authenticationTokenMetaData == null) {
            log.warn("Unsupported token type '" + roleMember.getTokenType() + "' in role '" + role.getName() + "'");
            return roleMember.getTokenType() + "(UNKNOWN): #" + roleMember.getTokenMatchKey();
        }
        final String tokenTypeString = getEjbcaWebBean().getText(authenticationTokenMetaData.getTokenType());
        final AccessMatchValue matchValue = authenticationTokenMetaData.getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey());
        if (matchValue == null) {
            log.warn("Unknown token match key " + roleMember.getTokenMatchKey() + " for " + roleMember.getTokenType() + " in role '" + role.getName() + "'");
            return tokenTypeString + ": " + '#'+String.valueOf(roleMember.getTokenMatchKey() + "(UNKNOWN)");
        }
        final String tokenMatchKeyString = getEjbcaWebBean().getText(matchValue.name());
        return tokenTypeString + ": " + tokenMatchKeyString;
    }

    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that is has been issued by a CA */
    public boolean isRenderTokenIssuerIdInput() {
        return getAccessMatchValue(getSelectedTokenType(), getSelectedTokenMatchKey()).isIssuedByCa();
    }

    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that is has been provided by Oauth */
    public boolean isRenderProviderInput() {
        return getAccessMatchValue(getSelectedTokenType(), getSelectedTokenMatchKey()).isIssuedByOauthProvider();
    }

    /** @return a List of (SelectItem<Integer, String>) authorized CAs */
    public List<SelectItem> getAvailableCas() {
        final List<SelectItem> availableCas = new ArrayList<>();
        final List<Integer> authorizedCaIds = caSession.getAuthorizedCaIds(getAdmin());
        for (final int caId : authorizedCaIds) {
            availableCas.add(new SelectItem(caId, getCaIdToNameMap().get(caId)));
        }
        super.sortSelectItemsByLabel(availableCas);
        return availableCas;
    }

    public List<SelectItem> getAvailableOauthProviders() {
        final List<SelectItem> availableProviders = new ArrayList<>();
        final OAuthConfiguration oAuthConfiguration = getOAuthConfiguration();
        if (oAuthConfiguration != null && oAuthConfiguration.getOauthKeys() != null) {
            Collection<OAuthKeyInfo> oAuthKeyInfos = oAuthConfiguration.getOauthKeys().values();
            for (final OAuthKeyInfo oAuthKeyInfo : oAuthKeyInfos) {
                availableProviders.add(new SelectItem(oAuthKeyInfo.getInternalId(), oAuthKeyInfo.getLabel()));
            }
            super.sortSelectItemsByLabel(availableProviders);
        }
        return availableProviders;
    }

    public OAuthConfiguration getOAuthConfiguration() {
        if (oAuthConfiguration == null) {
            oAuthConfiguration = (OAuthConfiguration) globalConfigurationSession
                    .getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        }
        return oAuthConfiguration;
    }

    /** @return the currently selected CA if any */
    public Integer getTokenIssuerId() { return tokenIssuerId; }
    /** Set the currently selected CA */
    public void setTokenIssuerId(final Integer tokenIssuerId) { this.tokenIssuerId = tokenIssuerId; }

    /** @return a human readable version of the RoleMember's tokenIsserId (CA name) */
    public String getTokenIssuerIdString(final RoleMember roleMember) {
        final int tokenIssuerId = roleMember.getTokenIssuerId();
        if (tokenIssuerId==RoleMember.NO_ISSUER) {
            return "-";
        }
        if (isTokenIssuerIdUsed(roleMember)) {
            final String caName = getCaIdToNameMap().get(tokenIssuerId);
            if (caName==null) {
                return super.getEjbcaWebBean().getText("UNKNOWNCAID") + " " + tokenIssuerId;
            } else {
                return caName;
            }
        } else {
            return String.valueOf(tokenIssuerId);
        }
    }

    public Integer getTokenProviderId() {
        return tokenProviderId;
    }

    public void setTokenProviderId(Integer tokenProviderId) {
        this.tokenProviderId = tokenProviderId;
    }

    /**
     * @return a human readable version of the RoleMember's tokenProviderId (CA name)
     */
    public String getTokenProviderIdString(final RoleMember roleMember) {
        final int tokenProviderId = roleMember.getTokenProviderId();
        if (tokenProviderId == RoleMember.NO_PROVIDER) {
            return "-";
        }
        if (getAccessMatchValue(roleMember.getTokenType(), roleMember.getTokenMatchKey()).isIssuedByOauthProvider()) {
            final OAuthKeyInfo oauthKeyInfo = getOAuthConfiguration().getOauthKeyById(tokenProviderId);
            if (oauthKeyInfo == null) {
                return super.getEjbcaWebBean().getText("UNKNOWNPROVIDERID") + " " + tokenProviderId;
            } else {
                return oauthKeyInfo.getLabel();
            }
        } else {
            return String.valueOf(tokenProviderId);
        }
    }

    /** @return the ViewScoped cache of the CA to name map or a fresh copy from the backend if none is present yet. */
    private Map<Integer, String> getCaIdToNameMap() {
        if (this.caIdToNameMap==null) {
            this.caIdToNameMap = caSession.getCAIdToNameMap();
        }
        return this.caIdToNameMap;
    }

    /** @return a human readable version of the RoleMember's tokenMatchOperator */
    public String getTokenMatchOperatorString(final RoleMember roleMember) {
        return getEjbcaWebBean().getText(AccessMatchType.matchFromDatabase(roleMember.getTokenMatchOperator()).name());
    }

    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that it needs a tokenMatchValue */
    public boolean isRenderTokenMatchValueInput() {
        return !getAccessMatchValue(getSelectedTokenType(), getSelectedTokenMatchKey()).getAvailableAccessMatchTypes().isEmpty();
    }

    /** @return the current tokenMatchValue */
    public String getTokenMatchValue() { return tokenMatchValue; }
    /** Set the current tokenMatchValue */
    public void setTokenMatchValue(final String tokenMatchValue) { this.tokenMatchValue = tokenMatchValue.trim(); }
    
    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that the tokenMatchValue is a hex certificate serial number */
    public boolean isRenderCertificateLink(final RoleMember roleMember) {
        return X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(roleMember.getTokenType()) &&
                X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue() == roleMember.getTokenMatchKey();
    }

    /** @return the tokenType from the currently selected tokenType and tokenMatchKey combo */
    private String getSelectedTokenType() {
        return matchWithSelected.split(":")[0];
    }
    /** @return the tokenMatchKey from the currently selected tokenType and tokenMatchKey combo */
    private int getSelectedTokenMatchKey() {
        return Integer.parseInt(matchWithSelected.split(":")[1]);
    }
    /** @return the AccessMatchValue from the specified tokenType and tokenMatchKey combo */
    private AccessMatchValue getAccessMatchValue(final String tokenType, final int tokenMatchKey) {
        final AuthenticationTokenMetaData metaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType);
        if (metaData != null) {
            return metaData.getAccessMatchValueIdMap().get(tokenMatchKey);
        } else {
            log.warn("Unsupported token type " + tokenType);
            return null;
        }
    }

    /** @return the current human readable description */
    public String getDescription() { return description; }
    /** Set the current human readable description */
    public void setDescription(final String description) { this.description = description.trim(); }

    /** Invoked by the admin when adding a new RoleMember. */
    public void actionAddRoleMember() {
        try {
            final String tokenType = getSelectedTokenType();
            final int tokenMatchKey = getSelectedTokenMatchKey();
            final AccessMatchValue accessMatchValue = getAccessMatchValue(tokenType, tokenMatchKey);
            final AccessMatchType accessMatchType;
            if (accessMatchValue.getAvailableAccessMatchTypes().isEmpty()) {
                accessMatchType = AccessMatchType.TYPE_UNUSED;
            } else {
                accessMatchType = getAccessMatchType(accessMatchValue);
            }

            if (AccessMatchType.TYPE_UNUSED.equals(accessMatchType)) {
                tokenMatchValue = "";
            } else {
                // Validate that a required tokenMatchValue has been entered
                if (StringUtils.isEmpty(tokenMatchValue)) {
                    super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "MATCHVALUEREQUIRED");
                    return;
                }
            }
            // Validate that the tokenMatchValue contains no illegal characters
            // (Check this here instead of using an f:validator validatorId="legalCharsValidator" since we might need to do PRG later)
            Set<String> invalidCharacters = StringTools.hasSqlStripChars(tokenMatchValue);
            if (!invalidCharacters.isEmpty()) {
                StringBuilder sb = new StringBuilder("");
                for (String error : invalidCharacters) {
                    sb.append(", " + error);
                }
                super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "INVALIDCHARS", sb.substring(2) );
                return;
            }
            // If the tokenMatchValue should be a hex number, validate that it is
            if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) &&
                    X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue()==tokenMatchKey) {
                tokenMatchValue = StringTools.removeAllWhitespaceAndColon(tokenMatchValue);
                try {
                    final BigInteger matchValueSerialNr = new BigInteger(tokenMatchValue, 16);
                    // If we require cert in database, the CA isn't external and the cert serial number doesn't exists for the matched CA,
                    // it's safe to assume that this was a user error (wrong CA selected or invalid serialnumber).
                    if (WebConfiguration.getRequireAdminCertificateInDatabase()) {
                        final String issuerDn = caSession.getCaSubjectDn(getCaIdToNameMap().get(tokenIssuerId));
                        final boolean isExternalCa = caSession.getCANoLog(getAdmin(), tokenIssuerId, null).getStatus() ==  CAConstants.CA_EXTERNAL;
                        if (!isExternalCa && !certificateStoreSession.existsByIssuerAndSerno(issuerDn, matchValueSerialNr)) {
                            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "WITH_SERIALNUMBER_UNKNOWN", tokenMatchValue, issuerDn);
                            return;
                        }
                    }
                    
                } catch (NumberFormatException e) {
                    super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "HEXREQUIRED");
                    return;
                } catch (AuthorizationDeniedException e) {
                    // Since the CA is selected from a drop down containing authorized CAs only. Occurrence is unlikely
                    super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "AUTHORIZATIONDENIED");
                    return;
                }
            }
            final int tokenIssuerId;
            if (accessMatchValue.isIssuedByCa()) {
                tokenIssuerId = this.tokenIssuerId;
            } else {
                tokenIssuerId = RoleMember.NO_ISSUER;
            }
            final int tokenProviderId = accessMatchValue.isIssuedByOauthProvider() ? this.tokenProviderId : RoleMember.NO_PROVIDER;
            try {
                // Persist the new role member
                final RoleMember roleMember = new RoleMember(tokenType, tokenIssuerId, tokenProviderId, tokenMatchKey,
                        accessMatchType.getNumericValue(), tokenMatchValue, role.getRoleId(), description);
                roleMemberSession.persist(getAdmin(), roleMember);                
            } catch (AuthorizationDeniedException e) {
                super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "AUTHORIZATIONDENIED");
            }
            
            // Only reset this one, since admin might want to add additional matches of the same type
            tokenMatchValue = "";
            // Trigger a reload of the RoleMember list (if this is an AJAX requests and no new viewscope will be created)
            roleMembers = null;
        } finally {
            nonAjaxPostRedirectGet();
        }
    }

    /** @return true if the RoleMember's tokenType and tokenMatchKey combo implies that it is issued by a CA */
    public boolean isTokenIssuerIdUsed(final RoleMember roleMember) {
        final AccessMatchValue matchKey = getAccessMatchValue(roleMember.getTokenType(), roleMember.getTokenMatchKey());
        return matchKey != null ? matchKey.isIssuedByCa() : true;
    }
    /** @return true if the RoleMember's tokenType and tokenMatchKey combo implies that it is issued by an Oauth provider */
    public boolean isTokenProviderIssuerIdUsed(final RoleMember roleMember) {
        return getAccessMatchValue(roleMember.getTokenType(), roleMember.getTokenMatchKey()).isIssuedByOauthProvider();
    }

    /** @return true if the RoleMember's tokenType and tokenMatchKey combo implies a tokenMatchValue is used */
    public boolean isTokenMatchValueUsed(final RoleMember roleMember) {
        final AccessMatchValue matchKey = getAccessMatchValue(roleMember.getTokenType(), roleMember.getTokenMatchKey());
        if (matchKey != null) {
            return !matchKey.getAvailableAccessMatchTypes().isEmpty();
        } else {
            return true;
        }
    }

    /** @return the RoleMember that has been selected for deletion */
    public RoleMember getRoleMemberToDelete() {
        return roleMemberToDelete;
    }
    /** @return true if a RoleMember that has been selected for deletion */
    public boolean isRenderDeleteRoleMember() {
        return roleMemberToDelete!=null;
    }
    /** Invoked by the admin to start the process of deleting a RoleMember */
    public void actionDeleteRoleMemberStart() {
        roleMemberToDelete = getRoleMembers().getRowData();
    }
    /** Invoked by the admin to cancel the process of deleting a RoleMember */
    public void actionDeleteRoleMemberReset() {
        roleMemberToDelete = null;
        nonAjaxPostRedirectGet();
    }
    /** Invoked by the admin to confirm the process of deleting a RoleMember */
    public void actionDeleteRoleMemberConfirm() {
        try {
            roleMemberSession.remove(getAdmin(), roleMemberToDelete.getId());
            super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ROLEMEMBERS_INFO_REMOVED");
            roleMembers = null;
            roleMemberToDelete = null;
            nonAjaxPostRedirectGet();
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLEMEMBERS_ERROR_UNAUTH", e.getMessage());
        }
    }
}
