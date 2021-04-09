

var ko = require("knockout");
var Constants = require("../Core/Constants");
var Browser = require("../Core/BrowserControl");
var Helpers = require("../Core/Helpers");
var ComponentEvent = require("../Core/ComponentEvent");
var ApiRequest = require("../Core/ApiRequest");
var Fido = require("../Core/Fido");
var PromiseHelpers = require("../Core/PromiseHelpers");
var GetOneTimeCodeHelper = require("../Core/GetOneTimeCodeHelper");
var Otc = require("../Core/OtcRequestControl");
var LoginConstants = require("./LoginConstants");
var ClientTracingConstants = require("../Core/ClientTracingConstants");

var requireCredIcon = require.context("images/CredentialOptions", false, /^.+\/cred_option_.+\.(png|svg)$/);
var requireProofIcon = require.context("images", false, /^.+\/picker_verify_.+\.(png|svg)$/);
var Host = null;

if (__IS_XBOX__)
{
    Host = require("../Core/XboxHost");
}

var w = window;
var StringHelpers = Helpers.String;
var ErrorData = Helpers.ErrorData;
var PaginatedState = Constants.PaginatedState;
var CredentialType = Constants.CredentialType;
var ApiErrorCodes = Constants.ApiErrorCodes;
var DialogId = Constants.DialogId;
var KeyCode = Constants.KeyCode;
var AllowedIdentitiesType = LoginConstants.AllowedIdentitiesType;
var BrowserHelper = Browser.Helper;
var ProofType = PROOF.Type;


function LoginCredentialPickerViewModel(params)
{
    var _this = this;

    
    var _serverData = params.serverData;
    var _availableCreds = params.availableCreds || [];
    var _evictedCreds = params.evictedCreds || [];
    var _useEvictedCredentials = params.useEvictedCredentials;
    var _isUserKnown = params.isUserKnown;
    var _flowToken = params.flowToken;
    var _username = params.username;
    var _isInitialView = params.isInitialView;
    var _serverError = params.serverError;
    var _isSignup = params.isSignup;
    

    
    var _strings = _serverData.str;
    var _checkApiCanary = _serverData.j;
    var _getOneTimeCodeUrl = _serverData.urlGetOneTimeCode;
    var _originalRequest = _serverData.C;
    var _showForgotUsername = _serverData.AU;
    var _forgotUsernameUrl = _serverData.r;
    var _allowedIdentities = _serverData.K;
    var _siteId = _serverData.i;
    var _clientId = _serverData.g;
    var _forwardedClientId = _serverData.H;
    var _noPaBubbleVersion = _serverData.h;
    var _allowEmailSelfServiceSignup = _serverData.aL;
    var _oidcDiscoveryEndpointFormatUrl = _serverData.aI;
    

    
    var _isSvgImageSupported = false;
    var _userCode = null;
    var _deviceCode = null;
    var _selectedProof = null;
    var _focusedHelpIcon = null;
    var _tileHelpClicked = false;
    var _credentials = [];
    

    
    _this.displayHelp = !_isUserKnown;
    _this.hasFido = false;
    _this.hasGitHub = false;
    _this.isInitialView = _isInitialView;
    _this.title = null;

    _this.error = ko.observable(_isInitialView && _serverError);
    _this.isPlatformAuthenticatorAvailable = ko.observable(false);
    _this.isRequestPending = ko.observable(false);
    _this.selectedCredential = ko.observable();
    _this.focusedCredential = ko.observable();
    _this.focusedHelpIcon = ko.observable();
    _this.useEvictedCredentials = ko.observable(!!_useEvictedCredentials);
    

    
    _this.onSwitchView = ComponentEvent.create();
    _this.onRedirect = ComponentEvent.create();
    _this.onSetPendingRequest = ComponentEvent.create();
    _this.onRegisterDialog = ComponentEvent.create();
    _this.onUnregisterDialog = ComponentEvent.create();
    _this.onShowDialog = ComponentEvent.create();
    _this.onUpdateFlowToken = ComponentEvent.create();
    

    
    _this.saveSharedData = function (sharedData)
    {
        if (_userCode && _deviceCode)
        {
            sharedData.remoteLoginUserCode = _userCode;
            sharedData.remoteLoginDeviceCode = _deviceCode;
        }

        if (_selectedProof)
        {
            sharedData.otcCredential =
                {
                    credType: CredentialType.OneTimeCode,
                    proof: _selectedProof
                };
        }
    };

    _this.getState = function ()
    {
        var state =
        {
            useEvictedCredentials: _this.useEvictedCredentials()
        };

        return state;
    };

    _this.restoreState = function (state)
    {
        if (state)
        {
            _this.useEvictedCredentials(state.useEvictedCredentials);
        }
    };

    _this.filteredCredentials = ko.pureComputed(
        function ()
        {
            var showDefaultCredentials = !_this.useEvictedCredentials();

            return ko.utils.arrayFilter(
                _credentials,
                function (credential)
                {
                    return credential.isDefault === showDefaultCredentials;
                });
        });
    

    
    _this.tile_onClick = function (credentialInfo)
    {
        if (_tileHelpClicked)
        {
            _tileHelpClicked = false;
            return;
        }

        if (credentialInfo.redirectUrl)
        {
            _this.onRedirect(credentialInfo.redirectUrl, credentialInfo.redirectPostParams);
        }
        else
        {
            var paginatedState = credentialInfo.paginatedState;

            switch (paginatedState)
            {
                case PaginatedState.RemoteLoginPolling:
                    _this.error(null);
                    _setIsRequestPending(true);

                    var apiRequest = new ApiRequest({ checkApiCanary: _checkApiCanary });
                    apiRequest.Json(
                        {
                            url: _getOneTimeCodeUrl,
                            eventId: ClientTracingConstants.EventIds.Api_GetOneTimeCode
                        },
                        { originalRequest: _originalRequest },
                        _getOneTimeCode_onSuccess,
                        _getOneTimeCode_onError,
                        Constants.DefaultRequestTimeout);

                    break;

                case PaginatedState.OneTimeCode:
                    _this.error(null);
                    _selectedProof = credentialInfo.proof;

                    if (_selectedProof.clearDigits)
                    {
                        _this.onSwitchView(PaginatedState.ProofConfirmation);
                    }
                    else
                    {
                        var otcParams = _getOneTimeCodeHelperParams();
                        var getOneTimeCodeHelper = new GetOneTimeCodeHelper(otcParams);
                        _setIsRequestPending(true);

                        getOneTimeCodeHelper.sendRequest();
                    }
                    break;

                default:
                    _this.onSwitchView(paginatedState);
                    break;
            }
        }
    };

    _this.tileHelp_onClick = function (credentialInfo)
    {
        _tileHelpClicked = true;
        _focusedHelpIcon = credentialInfo.helpDialogId;
        _this.focusedHelpIcon(DialogId.None);

        _this.onShowDialog(_focusedHelpIcon)
            .then(
                function ()
                {
                    _this.focusedHelpIcon(_focusedHelpIcon);
                });
    };

    _this.onCredentialSelected = function (credentialInfo)
    {
        _this.selectedCredential(credentialInfo);
    };

    _this.setDefaultFocus = function ()
    {
        if (_focusedHelpIcon)
        {
            _this.focusedHelpIcon(_focusedHelpIcon);
        }
        else
        {
            _this.focusedCredential(_this.selectedCredential() || _this.filteredCredentials()[0]);
        }
    };

    _this.onItemKeyDown = function (credentialInfo, e)
    {
        var previousCredential = null;
        var nextCredential = null;
        var credentials = _this.filteredCredentials();

        if (e.keyCode === KeyCode.ArrowUp || e.keyCode === KeyCode.ArrowDown)
        {
            for (var index = 0; index < credentials.length; index++)
            {
                if (credentials[index] === credentialInfo)
                {
                    previousCredential = credentials[index - 1] || credentialInfo;
                    nextCredential = credentials[index + 1] || credentialInfo;
                    break;
                }
            }
        }

        switch (e.keyCode)
        {
            case KeyCode.PageUp:
            case KeyCode.Home:
                _this.focusedCredential(credentials[0]);
                break;

            case KeyCode.ArrowUp:
                _this.focusedCredential(previousCredential);
                break;

            case KeyCode.PageDown:
            case KeyCode.End:
                _this.focusedCredential(credentials[credentials.length - 1]);
                break;

            case KeyCode.ArrowDown:
                _this.focusedCredential(nextCredential);
                break;

            case KeyCode.Space:
                _this.selectedCredential(credentialInfo);
                break;

            case KeyCode.Enter:
                if (_this.selectedCredential() === credentialInfo)
                {
                    _this.tile_onClick(_this.selectedCredential());
                }
                else
                {
                    _this.selectedCredential(credentialInfo);
                }
                break;

            default:
                
                return true;
        }

        return false;
    };

    _this.primaryButton_onClick = function ()
    {
        _this.tile_onClick(_this.selectedCredential());
    };

    _this.secondaryButton_onClick = function ()
    {
        _this.onSwitchView(PaginatedState.Previous);
    };
    

    
    function _getCredIconImageName(credName, useLight)
    {
        return Helpers.String.format(
            "./cred_option_{0}{1}.{2}",
            credName,
            useLight ? "_white" : "",
            _isSvgImageSupported ? "svg" : "png");
    }

    function _getProofImageName(proofType, useLight)
    {
        var proofName = "";

        switch (proofType)
        {
            case ProofType.Email:
                proofName = "email";
                break;

            case ProofType.SMS:
                proofName = "sms";
                break;

            case ProofType.Voice:
                proofName = "call";
                break;
        }

        return Helpers.String.format(
            "./picker_verify_{0}{1}.{2}",
            proofName,
            useLight ? "_white" : "",
            _isSvgImageSupported ? "svg" : "png");
    }

    function _getOneTimeCode_onSuccess(result)
    {
        _userCode = result.UserCode;
        _deviceCode = result.DeviceCode;
        _setIsRequestPending(false);

        _this.onSwitchView(PaginatedState.RemoteLoginPolling);
    }

    function _getOneTimeCode_onError(response)
    {
        _setIsRequestPending(false);
        var errorText = "";

        if (response && response.error)
        {
            switch (response.error.code)
            {
                case ApiErrorCodes.AuthFailure:
                    errorText = _strings["CT_PWD_STR_Error_FlowTokenExpired"];
                    break;

                default:
                    errorText = _strings["CT_PWD_STR_Error_GetOneTimeCodeError"];
                    break;
            }
        }
        else
        {
            errorText = _strings["CT_PWD_STR_Error_GetOneTimeCodeError"];
        }

        if (errorText)
        {
            _this.error(new ErrorData(errorText, null));
        }
    }

    function _checkPlatformAuthenticatorAvailable(fidoCredential)
    {
        PromiseHelpers.throwUnhandledExceptionOnRejection(
            Fido.isPlatformAuthenticatorAvailable()
                .then(null, function () { return false; })
                .then(
                    function (isPlatformAuthenticatorAvailable)
                    {
                        if (isPlatformAuthenticatorAvailable)
                        {
                            fidoCredential.description(_isUserKnown ? _strings["CT_STR_CredentialPicker_Option_Fido_KnownUser"] : _strings["CT_STR_CredentialPicker_Option_Fido"]);
                            fidoCredential.helpText(_strings["CT_STR_CredentialPicker_Option_Help_Fido"]);
                            fidoCredential.ariaLabel(_strings["CT_STR_CredentialPicker_Help_Desc_Fido"]);

                            _this.isPlatformAuthenticatorAvailable(true);
                        }
                    }));
    }

    function _getOneTimeCodeHelperParams()
    {
        var otcParams =
            {
                username: StringHelpers.cleanseUsername(_username),
                proofData: _selectedProof.data,
                proofType: _selectedProof.type,
                purpose: _selectedProof.isNopa ? Otc.Purpose.NoPassword : Otc.Purpose.OtcLogin,
                flowToken: _flowToken,
                isEncrypted: _selectedProof.isEncrypted,
                siteId: _siteId,
                clientId: _clientId,
                forwardedClientId: _forwardedClientId,
                noPaBubbleVersion: _noPaBubbleVersion,
                successCallback: _sendOneTimeCode_onSuccess,
                failureCallback: _sendOneTimeCode_onFail
            };

        if (otcParams.isEncrypted)
        {
            switch (_selectedProof.type)
            {
                case ProofType.Email:
                    otcParams.proofConfirmation = _selectedProof.display;
                    break;
                case ProofType.SMS:
                case ProofType.Voice:
                    otcParams.proofConfirmation = StringHelpers.cleanseUsername(_selectedProof.display).slice(-4);
                    break;
            }
        }

        return otcParams;
    }

    function _sendOneTimeCode_onSuccess(response)
    {
        _setFlowToken(response);

        _setIsRequestPending(false);
        _this.onSwitchView(PaginatedState.OneTimeCode);
    }

    function _sendOneTimeCode_onFail(response)
    {
        var errorString;
        var errorNumericId = response.getOtcStatus();

        _setFlowToken(response);

        switch (errorNumericId)
        {
            case Otc.Status.FTError:
                errorString = _strings["CT_OTC_STR_Error_FlowExpired"];
                break;
            default:
                errorString = _selectedProof.str["CT_OTCS_STR_Error_SendCodeServer"] || "";
                break;
        }

        _setIsRequestPending(false);
        _this.error(new ErrorData(errorString, null));
    }

    function _setFlowToken(response)
    {
        if (response)
        {
            if (response.getFlowToken)
            {
                _flowToken = response.getFlowToken();
                _this.onUpdateFlowToken(_flowToken);
            }
            else if (response.FlowToken)
            {
                _flowToken = response.FlowToken;
                _this.onUpdateFlowToken(_flowToken);
            }
        }
    }

    function _setIsRequestPending(pending)
    {
        _this.isRequestPending(pending);
        _this.onSetPendingRequest(pending);
    }

    function _buildSortedCredentialList()
    {
        if (_isSignup && _allowEmailSelfServiceSignup)
        {
            _credentials.push(
                {
                    credType: "email",
                    lightIconUrl: requireProofIcon(_getProofImageName(ProofType.Email), true),
                    darkIconUrl: requireProofIcon(_getProofImageName(ProofType.Email), false),
                    description: ko.observable(_strings["CT_STR_SignupCred_UseEmail"]),
                    helpText: ko.observable(null),
                    ariaLabel: ko.observable(null),
                    helpDialogId: null,
                    paginatedState: PaginatedState.SignupUsername,
                    proof: null,
                    proofValue: null,
                    redirectUrl: null,
                    weight: -1,
                    isDefault: true,
                    redirectPostParams: null
                });
        }

        ko.utils.arrayForEach(
            _availableCreds.concat(_evictedCreds),
            function (credential)
            {
                var lightIconUrl = null;
                var darkIconUrl = null;
                var description = null;
                var helpText = null;
                var ariaLabel = null;
                var helpDialogId = null;
                var paginatedState = null;
                var proof = null;
                var proofValue = null;
                var redirectUrl = null;
                var redirectPostParams = null;
                var weight = 0;
                var isDefault = true;

                switch (credential.credType)
                {
                    case CredentialType.RemoteLogin:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("remote", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("remote", false));
                        description = _strings["CT_PWD_STR_RemoteLoginLink"];
                        paginatedState = PaginatedState.RemoteLoginPolling;
                        weight = 1;
                        break;

                    case CredentialType.Fido:
                        _this.hasFido = true;

                        lightIconUrl = requireCredIcon(_getCredIconImageName("fido", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("fido", false));
                        description = _isUserKnown ? _strings["CT_STR_CredentialPicker_Option_FidoCrossPlatform_KnownUser"] : _strings["CT_STR_CredentialPicker_Option_FidoCrossPlatform"];
                        helpText = _strings["CT_STR_CredentialPicker_Option_Help_FidoCrossPlatform"];
                        ariaLabel = _strings["CT_STR_CredentialPicker_Help_Desc_FidoCrossPlatform"];
                        helpDialogId = DialogId.FidoHelp;
                        paginatedState = PaginatedState.Fido;
                        weight = 2;
                        break;

                    case CredentialType.RemoteNGC:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("authenticator", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("authenticator", false));
                        description = _strings["CT_STR_CredentialPicker_Option_AuthenticatorApp"];
                        paginatedState = PaginatedState.RemoteNGC;
                        weight = 3;
                        break;

                    case CredentialType.Password:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("password", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("password", false));
                        description = _strings["CT_STR_CredentialPicker_Option_Password"];
                        paginatedState = PaginatedState.Password;
                        isDefault = credential.isDefault !== false; 
                        weight = 4;
                        break;

                    case CredentialType.Federation:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("federated", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("federated", false));
                        description = _strings["CT_STR_CredentialPicker_Option_Federated"];
                        paginatedState = PaginatedState.IdpRedirect;
                        weight = 5;
                        break;

                    case CredentialType.LinkedIn:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("linkedin", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("linkedin", false));
                        description = _strings["CT_PWD_STR_UseLinkedIn_Link"];
                        redirectUrl = credential.redirectUrl;

                        if (_allowedIdentities === AllowedIdentitiesType.Both)
                        {
                            helpText = _strings["CT_STR_CredentialPicker_PersonalAccountsOnly"];
                        }

                        weight = 6;
                        break;

                    case CredentialType.OtherMicrosoftIdpFederation:
                        
                        lightIconUrl = darkIconUrl = requireCredIcon(_getCredIconImageName("microsoft", false));
                        description = _isSignup ? _strings["CT_STR_SignupCred_UseMicrosoft"] : _strings["CT_PWD_STR_UseMicrosoft_Link"];
                        redirectUrl = credential.redirectUrl;

                        weight = 7;
                        break;

                    case CredentialType.GitHub:
                        _this.hasGitHub = true;

                        lightIconUrl = requireCredIcon(_getCredIconImageName("github", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("github", false));
                        description = _strings["CT_PWD_STR_UseGitHub_Link"];
                        ariaLabel = _strings["CT_STR_CredentialPicker_Help_Desc_GitHub"];
                        helpDialogId = DialogId.GitHubHelp;
                        redirectUrl = credential.redirectUrl;

                        if (_allowedIdentities === AllowedIdentitiesType.Both)
                        {
                            helpText = _strings["CT_STR_CredentialPicker_PersonalAccountsOnly"];
                        }

                        weight = 8;
                        break;

                    case CredentialType.Google:
                        
                        lightIconUrl = darkIconUrl = requireCredIcon(_getCredIconImageName("google", false));
                        description = _isSignup ? _strings["CT_STR_SignupCred_UseGoogle"] : _strings["CT_PWD_STR_UseGoogle_Link"];
                        redirectUrl = credential.redirectUrl;

                        weight = 9;
                        break;

                    case CredentialType.Facebook:
                        
                        lightIconUrl = darkIconUrl = requireCredIcon("./cred_option_facebook.png");
                        description = _isSignup ? _strings["CT_STR_SignupCred_UseFacebook"] : _strings["CT_PWD_STR_UseFacebook_Link"];
                        redirectUrl = credential.redirectUrl;

                        weight = 10;
                        break;

                    case CredentialType.OneTimeCode:
                        proof = credential.proof;

                        if (proof && (proof.type === ProofType.Email || proof.type === ProofType.SMS || proof.type === ProofType.Voice))
                        {
                            lightIconUrl = requireProofIcon(_getProofImageName(proof.type, true));
                            darkIconUrl = requireProofIcon(_getProofImageName(proof.type, false));
                            description = (proof.str && proof.str["CT_OTCS_STR_ProofOptionText"]) || "";
                            paginatedState = PaginatedState.OneTimeCode;
                            weight = proof.type === ProofType.Email ? 11 : 12;
                            proofValue = proof.type + ":" + proof.data;
                            isDefault = proof.isDefault;
                        }
                        break;

                    case CredentialType.AccessPass:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("accesspass", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("accesspass", false));
                        description = _strings["CT_PWD_STR_Login_CredPicker_Option_AccessPass"];
                        paginatedState = PaginatedState.AccessPass;
                        weight = 13;
                        break;

                    case CredentialType.Certificate:
                        lightIconUrl = requireCredIcon(_getCredIconImageName("certificate", true));
                        darkIconUrl = requireCredIcon(_getCredIconImageName("certificate", false));
                        description = _strings["CT_STR_CredentialPicker_Option_Certificate"];
                        redirectUrl = credential.redirectUrl;
                        redirectPostParams = credential.redirectPostParams;

                        weight = 14;
                        break;

                    default:
                        return;
                }

                
                if (description)
                {
                    _credentials.push(
                        {
                            credType: credential.credType,
                            lightIconUrl: lightIconUrl,
                            darkIconUrl: darkIconUrl,
                            description: ko.observable(description),
                            helpText: ko.observable(helpText),
                            ariaLabel: ko.observable(ariaLabel),
                            helpDialogId: helpDialogId,
                            paginatedState: paginatedState,
                            proof: proof,
                            proofValue: proofValue,
                            redirectUrl: redirectUrl,
                            weight: weight,
                            isDefault: isDefault,
                            redirectPostParams: redirectPostParams
                        });

                    if (credential.credType === CredentialType.Fido)
                    {
                        var fidoCredential = _credentials[_credentials.length - 1];

                        _checkPlatformAuthenticatorAvailable(fidoCredential);
                    }
                }
            });

        if (_oidcDiscoveryEndpointFormatUrl)
        {
            _credentials.push(
                {
                    credType: "organization",
                    lightIconUrl: require("images/picker_account_aad.png"),
                    darkIconUrl: require("images/picker_account_aad.png"),
                    description: ko.observable(_strings["CT_STR_CredentialPicker_Option_Exid"]),
                    helpText: ko.observable(_strings["CT_STR_CredentialPicker_Help_Desc_Exid"]),
                    ariaLabel: ko.observable(null),
                    helpDialogId: null,
                    paginatedState: PaginatedState.SearchOrganization,
                    proof: null,
                    proofValue: null,
                    redirectUrl: null,
                    weight: 98,
                    isDefault: true,
                    redirectPostParams: null
                });
        }

        if (_showForgotUsername && !_isUserKnown)
        {
            _credentials.push(
                {
                    credType: null,
                    lightIconUrl: requireCredIcon(_getCredIconImageName("forgot", true)),
                    darkIconUrl: requireCredIcon(_getCredIconImageName("forgot", false)),
                    description: ko.observable(_strings["CT_STR_CredentialPicker_Option_ForgotUsername"]),
                    helpText: ko.observable(_allowedIdentities === AllowedIdentitiesType.Both ? _strings["CT_STR_CredentialPicker_PersonalAccountsOnly"] : null),
                    ariaLabel: ko.observable(null),
                    helpDialogId: null,
                    paginatedState: null,
                    proof: null,
                    proofValue: null,
                    redirectUrl: _forgotUsernameUrl,
                    weight: 99,
                    isDefault: true,
                    redirectPostParams: null
                });
        }

        _credentials.sort(
            function (a, b)
            {
                return a.weight - b.weight;
            });
    }

    (function _initialize()
    {
        _isSvgImageSupported = BrowserHelper.isSvgImgSupported();

        var title = _strings["CT_STR_CredentialPicker_Title_NoUser"];

        if (_isSignup)
        {
            title = _strings["CT_STR_SignupUsername_Title"];
        }
        else if (_isUserKnown)
        {
            title = _strings["CT_STR_CredentialPicker_Title"];
        }

        _this.title = title;

        _buildSortedCredentialList();

        if (Host && Host.showKeyboard)
        {
            Host.showKeyboard(false);
        }
    })();
    
}

ko.components.register("login-credential-picker-view",
    {
        viewModel: LoginCredentialPickerViewModel,
        template: require("html/LoginPage/LoginCredentialPickerViewHtml.html"),
        synchronous: !w.ServerData.A || BrowserHelper.isStackSizeGreaterThan(w.ServerData.A),
        enableExtensions: true
    });

module.exports = LoginCredentialPickerViewModel;