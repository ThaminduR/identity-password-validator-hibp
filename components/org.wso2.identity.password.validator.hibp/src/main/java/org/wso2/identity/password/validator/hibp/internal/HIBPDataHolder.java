/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.password.validator.hibp.internal;

import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * Holds the services this connector needs. The governance service provides the connector's
 * per-organization configuration, which is also what gives it a presence in the Console.
 */
public class HIBPDataHolder {

    private static final HIBPDataHolder INSTANCE = new HIBPDataHolder();

    private IdentityGovernanceService identityGovernanceService;

    private HIBPDataHolder() {

    }

    public static HIBPDataHolder getInstance() {

        return INSTANCE;
    }

    public IdentityGovernanceService getIdentityGovernanceService() {

        return identityGovernanceService;
    }

    public void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        this.identityGovernanceService = identityGovernanceService;
    }
}
