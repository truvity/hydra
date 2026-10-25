# CreatePreAuthorizedCodeBody

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClientId** | Pointer to **string** | The OAuth 2.0 client ID to bind the code to. If omitted, any client (or anonymous if configured) can redeem the code. | [optional] 
**CredentialConfigurationIds** | **[]string** | The credential configuration IDs the Credential Issuer plans to offer. Defines the authorization envelope — the Wallet can request a subset via authorization_details at the token endpoint. | 
**Scope** | Pointer to **string** | Space-separated scopes to grant. Include \&quot;offline\&quot; or \&quot;offline_access\&quot; to enable refresh token issuance. | [optional] 
**SessionExtra** | Pointer to **map[string]interface{}** | Extra claims to embed in the pre-authorized code session. These claims will be available via token introspection in the &#x60;ext&#x60; field after the code is exchanged for an access token. Use this to pass correlation identifiers (e.g., offer_id) from the Credential Issuer to the token session. | [optional] 
**TxCode** | Pointer to **string** | Transaction code in plaintext. The AS computes the SHA-256 hash before storage. The plaintext is never stored. | [optional] 
**TxCodeInputMode** | Pointer to **string** | Input mode for the transaction code: \&quot;numeric\&quot; or \&quot;text\&quot;. Stored for metadata completeness (included in Credential Offer by the Issuer). | [optional] 
**TxCodeLength** | Pointer to **int64** | Expected length of the transaction code. Stored for metadata completeness. | [optional] 

## Methods

### NewCreatePreAuthorizedCodeBody

`func NewCreatePreAuthorizedCodeBody(credentialConfigurationIds []string, ) *CreatePreAuthorizedCodeBody`

NewCreatePreAuthorizedCodeBody instantiates a new CreatePreAuthorizedCodeBody object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCreatePreAuthorizedCodeBodyWithDefaults

`func NewCreatePreAuthorizedCodeBodyWithDefaults() *CreatePreAuthorizedCodeBody`

NewCreatePreAuthorizedCodeBodyWithDefaults instantiates a new CreatePreAuthorizedCodeBody object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetClientId

`func (o *CreatePreAuthorizedCodeBody) GetClientId() string`

GetClientId returns the ClientId field if non-nil, zero value otherwise.

### GetClientIdOk

`func (o *CreatePreAuthorizedCodeBody) GetClientIdOk() (*string, bool)`

GetClientIdOk returns a tuple with the ClientId field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClientId

`func (o *CreatePreAuthorizedCodeBody) SetClientId(v string)`

SetClientId sets ClientId field to given value.

### HasClientId

`func (o *CreatePreAuthorizedCodeBody) HasClientId() bool`

HasClientId returns a boolean if a field has been set.

### GetCredentialConfigurationIds

`func (o *CreatePreAuthorizedCodeBody) GetCredentialConfigurationIds() []string`

GetCredentialConfigurationIds returns the CredentialConfigurationIds field if non-nil, zero value otherwise.

### GetCredentialConfigurationIdsOk

`func (o *CreatePreAuthorizedCodeBody) GetCredentialConfigurationIdsOk() (*[]string, bool)`

GetCredentialConfigurationIdsOk returns a tuple with the CredentialConfigurationIds field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCredentialConfigurationIds

`func (o *CreatePreAuthorizedCodeBody) SetCredentialConfigurationIds(v []string)`

SetCredentialConfigurationIds sets CredentialConfigurationIds field to given value.


### GetScope

`func (o *CreatePreAuthorizedCodeBody) GetScope() string`

GetScope returns the Scope field if non-nil, zero value otherwise.

### GetScopeOk

`func (o *CreatePreAuthorizedCodeBody) GetScopeOk() (*string, bool)`

GetScopeOk returns a tuple with the Scope field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScope

`func (o *CreatePreAuthorizedCodeBody) SetScope(v string)`

SetScope sets Scope field to given value.

### HasScope

`func (o *CreatePreAuthorizedCodeBody) HasScope() bool`

HasScope returns a boolean if a field has been set.

### GetSessionExtra

`func (o *CreatePreAuthorizedCodeBody) GetSessionExtra() map[string]interface{}`

GetSessionExtra returns the SessionExtra field if non-nil, zero value otherwise.

### GetSessionExtraOk

`func (o *CreatePreAuthorizedCodeBody) GetSessionExtraOk() (*map[string]interface{}, bool)`

GetSessionExtraOk returns a tuple with the SessionExtra field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSessionExtra

`func (o *CreatePreAuthorizedCodeBody) SetSessionExtra(v map[string]interface{})`

SetSessionExtra sets SessionExtra field to given value.

### HasSessionExtra

`func (o *CreatePreAuthorizedCodeBody) HasSessionExtra() bool`

HasSessionExtra returns a boolean if a field has been set.

### GetTxCode

`func (o *CreatePreAuthorizedCodeBody) GetTxCode() string`

GetTxCode returns the TxCode field if non-nil, zero value otherwise.

### GetTxCodeOk

`func (o *CreatePreAuthorizedCodeBody) GetTxCodeOk() (*string, bool)`

GetTxCodeOk returns a tuple with the TxCode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCode

`func (o *CreatePreAuthorizedCodeBody) SetTxCode(v string)`

SetTxCode sets TxCode field to given value.

### HasTxCode

`func (o *CreatePreAuthorizedCodeBody) HasTxCode() bool`

HasTxCode returns a boolean if a field has been set.

### GetTxCodeInputMode

`func (o *CreatePreAuthorizedCodeBody) GetTxCodeInputMode() string`

GetTxCodeInputMode returns the TxCodeInputMode field if non-nil, zero value otherwise.

### GetTxCodeInputModeOk

`func (o *CreatePreAuthorizedCodeBody) GetTxCodeInputModeOk() (*string, bool)`

GetTxCodeInputModeOk returns a tuple with the TxCodeInputMode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCodeInputMode

`func (o *CreatePreAuthorizedCodeBody) SetTxCodeInputMode(v string)`

SetTxCodeInputMode sets TxCodeInputMode field to given value.

### HasTxCodeInputMode

`func (o *CreatePreAuthorizedCodeBody) HasTxCodeInputMode() bool`

HasTxCodeInputMode returns a boolean if a field has been set.

### GetTxCodeLength

`func (o *CreatePreAuthorizedCodeBody) GetTxCodeLength() int64`

GetTxCodeLength returns the TxCodeLength field if non-nil, zero value otherwise.

### GetTxCodeLengthOk

`func (o *CreatePreAuthorizedCodeBody) GetTxCodeLengthOk() (*int64, bool)`

GetTxCodeLengthOk returns a tuple with the TxCodeLength field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTxCodeLength

`func (o *CreatePreAuthorizedCodeBody) SetTxCodeLength(v int64)`

SetTxCodeLength sets TxCodeLength field to given value.

### HasTxCodeLength

`func (o *CreatePreAuthorizedCodeBody) HasTxCodeLength() bool`

HasTxCodeLength returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


