using NearClientUnity.KeyStores;
using NearClientUnity.Utilities;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Dynamic;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading.Tasks;
using System.Web;
using System.Web.Util;
using NearClientUnity.Providers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace NearClientUnity
{
    public class WalletAccount
    {
        private const string LocalStorageKeySuffix = "_wallet_auth_key";
        private const string LoginWalletUrlSuffix = "/login/";
        private const string PendingAccessKeyPrefix = "pending_key";

        private dynamic _authData = new ExpandoObject();
        private string _authDataKey;
        private IExternalAuthService _authService;
        private IExternalAuthStorage _authStorage;
        private KeyStore _keyStore;        
        private string _networkId;
        private string _walletBaseUrl;

        public WalletAccount(Near near, string appKeyPrefix, IExternalAuthService authService, IExternalAuthStorage authStorage)
        {
            _networkId = near.Config.NetworkId;
            _walletBaseUrl = near.Config.WalletUrl;
            appKeyPrefix = string.IsNullOrEmpty(appKeyPrefix) || string.IsNullOrWhiteSpace(appKeyPrefix)
                ? "default"
                : appKeyPrefix;
            _authDataKey = $"{appKeyPrefix}{LocalStorageKeySuffix}";
            _keyStore = (near.Connection.Signer as InMemorySigner).KeyStore;
            _authService = authService;
            _authStorage = authStorage;

           
            if (_authStorage.HasKey(_authDataKey))
            {
                _authData = JObject.Parse(_authStorage.GetValue(_authDataKey));
            }
            else
            {
                _authData.AccountId = null;
                _authData.AllKeys = new List<string>();
            }
        }

        public IExternalAuthStorage NearAuthStorage => _authStorage;

        public async Task CompleteSignIn(string url)
        {
            HttpEncoder.Current = HttpEncoder.Default;
            Uri uri = new Uri(url);
            string publicKey = HttpUtility.ParseQueryString(uri.Query).Get("public_key");
            string accountId = HttpUtility.ParseQueryString(uri.Query).Get("account_id");
            string allKeys = HttpUtility.ParseQueryString(uri.Query).Get("all_keys");
            
            _authData.AccountId = accountId;
            _authData.AllKeys = allKeys;

            try
            {
                _authStorage.Add(_authDataKey, JsonConvert.SerializeObject(_authData));                
                await MoveKeyFromTempToPermanent(accountId, publicKey);
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public string GetAccountId()
        {
            return _authData.AccountId ?? "";
        }

        public bool IsSignedIn()
        {
            if (_authData.AccountId == null) return false;
            return true;
        }

        public async Task<bool> RequestSignIn(string contractId, string title, Uri successUrl, Uri failureUrl, Uri appUrl)
        {
            if (!string.IsNullOrWhiteSpace(GetAccountId())) return true;
            if (await _keyStore.GetKeyAsync(_networkId, GetAccountId()) != null) return true;

            var accessKey = KeyPair.FromRandom("ed25519");

            var url = new UriBuilder(_walletBaseUrl + LoginWalletUrlSuffix);

            url.Query = new FormUrlEncodedContent(new Dictionary<string, string>()
            {
                { "title", title },
                { "contract_id", contractId },
                { "success_url", successUrl.AbsoluteUri },
                { "failure_url", failureUrl.AbsoluteUri },
                { "app_url", appUrl.AbsoluteUri},
                { "public_key", accessKey.GetPublicKey().ToString() },
            }).ReadAsStringAsync().Result;

            await _keyStore.SetKeyAsync(_networkId, PendingAccessKeyPrefix + accessKey.GetPublicKey(), accessKey);
            return _authService.OpenUrl(url.Uri.AbsoluteUri);
        }

        public void SignOut()
        {
            _authData = new ExpandoObject();
            _authData.AccountId = null;
            _authStorage.DeleteKey(_authDataKey);
        }

        private async Task MoveKeyFromTempToPermanent(string accountId, string publicKey)
        {
            var pendingAccountId = PendingAccessKeyPrefix + publicKey;
            KeyPair keyPair;
            try
            {
                keyPair = await _keyStore.GetKeyAsync(_networkId, pendingAccountId);
            }
            catch (Exception)
            {
                throw new Exception("Wallet account error: no KeyPair");
            }

            try
            {
                await _keyStore.SetKeyAsync(_networkId, accountId, keyPair);
            }
            catch (Exception e)
            {
                throw e;
            }

            try
            {
                await _keyStore.RemoveKeyAsync(_networkId, PendingAccessKeyPrefix + publicKey);
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        
        /*
         async accessKeyMatchesTransaction(accessKey, receiverId, actions) {
            const { access_key: { permission } } = accessKey;
            if (permission === 'FullAccess') {
                return true;
            }
            if (permission.FunctionCall) {
                const { receiver_id: allowedReceiverId, method_names: allowedMethods } = permission.FunctionCall;
            if (allowedReceiverId === this.accountId && allowedMethods.includes(MULTISIG_HAS_METHOD)) {
                return true;
            }
            if (allowedReceiverId === receiverId) {
                    if (actions.length !== 1) {
                        return false;
                    }
                    const [{ functionCall }] = actions;
                    return functionCall &&
                           (!functionCall.deposit || functionCall.deposit.toString() === '0') && // TODO: Should support charging amount smaller than allowance?
                           (allowedMethods.length === 0 || allowedMethods.includes(functionCall.methodName));
                    // TODO: Handle cases when allowance doesn't have enough to pay for gas
                }
            }
            // TODO: Support other permissions than FunctionCall
            return false;
        }
        */

        private async Task<FinalExecutionOutcome> SignAndSendTransactionAsync(string receiverId, Action[] actions, Account account, Connection connection)
        {
            PublicKey localKey = await connection.Signer.GetPublicKeyAsync();
            dynamic accessKey = AccessKeyForTransaction(account, receiverId, actions, localKey);
            if (accessKey == null)
            {
                throw new Exception($"Cannot find matching key for transaction sent to {receiverId}");
            }

            if (localKey != null && localKey.ToString() == accessKey.public_key)
            {
                try
                {
                    return await account.SignAndSendTransactionAsync(receiverId, actions);
                }
                catch (Exception ex) {
                    // TODO: type error
                    if (ex.Message == "NotEnoughAllowance")
                    {
                        accessKey = await this.AccessKeyForTransaction(account, receiverId, actions, null);
                    }
                    else {
                        throw;
                    }
                }
            }

            var block = await connection.Provider.GetBlockAsync();
        }
        
        private bool AccessKeyMatchesTransaction(dynamic accessKey, string receiverId, Action[] actions)
        {
            if (accessKey.permission == "FullAccess")
            {
                return true;
            }
            // else PermissionType == FunctionCall
            List<string> allowedMethods = accessKey.permission.FunctionCall.method_names.ToList();
            string allowedReceiverId = accessKey.permission.FunctionCall.receiver_id;
            if (allowedReceiverId == GetAccountId() && allowedMethods.Contains("add_request_and_confirm"))
            {
                return true;
            }

            if (allowedReceiverId == receiverId)
            {
                if (actions.Length != 1)
                {
                    return false;
                }

                var action = actions[0];
                return action != null && (action.Args.Deposit == 0) &&
                       (allowedMethods.Count == 0 || allowedMethods.Contains(action?.Args.MethodName));
            }

            return false;
        }

        private async Task<dynamic> AccessKeyForTransaction(Account account, string receiverId, Action[] actions, PublicKey localKey)
        {
            var rawAccessKeys = await account.GetAccessKeysAsync();
            var accessKeys = new List<dynamic>();

            foreach (dynamic key in rawAccessKeys.keys)
            {
                accessKeys.Add(key);
            }
            
            var accessKey = accessKeys.ToList().Find(key => key.public_key.toString() == localKey.ToString());
            
            if (accessKey && AccessKeyMatchesTransaction(accessKey, receiverId, actions))
            {
                return accessKey;
            }

            var walletKeys = new List<string>();
            foreach (dynamic key in _authData.AllKeys)
            {
                accessKeys.Add(key);
            }
            
            foreach (var key in accessKeys)
            {
                if (walletKeys.Contains(key.public_key) && AccessKeyMatchesTransaction(key, receiverId, actions))
                {
                    return key;
                }
            }
            
            return null;
        }
    }
}