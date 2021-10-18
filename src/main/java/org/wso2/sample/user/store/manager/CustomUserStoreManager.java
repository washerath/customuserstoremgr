/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.sample.user.store.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.Map;

public class CustomUserStoreManager extends JDBCUserStoreManager {

    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);
    Integer tenantId;

    public CustomUserStoreManager() {
    }

    public CustomUserStoreManager(org.wso2.carbon.user.api.RealmConfiguration realmConfig,
                                  Map<String, Object> properties,
                                  ClaimManager claimManager,
                                  ProfileConfigurationManager profileManager,
                                  UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId, false);
        this.tenantId = tenantId;
    }

    @Override
    protected boolean authenticate(final String username, final Object credential, final boolean domainProvided) throws UserStoreException {
        boolean isAuthed = false;
        RealmService realmService = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(RealmService.class);
        try {
            UserStoreManager userStoreManagerROLDAP =
                    ((UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager())
                            .getSecondaryUserStoreManager(CustomUserStoreConstants.LDAP_DOMAIN);
            boolean isAuthenticatedAgainstLDAP = userStoreManagerROLDAP.authenticate(username, credential);
            if (isAuthenticatedAgainstLDAP) {
                UserStoreManager userStoreManagerJDBC =
                        ((UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager())
                                .getSecondaryUserStoreManager(CustomUserStoreConstants.JDBC_DOMAIN);

                if (userStoreManagerJDBC.isExistingUser(CustomUserStoreConstants.JDBC_DOMAIN + "/" + username)) {
                    isAuthed = true;
                }
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Unable to get the user store manager: " + e.getMessage(), e);
        }
        return isAuthed;
    }
}