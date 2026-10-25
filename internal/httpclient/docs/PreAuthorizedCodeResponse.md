# PreAuthorizedCodeResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ExpiresAt** | **string** | RFC 3339 expiry timestamp for the pre-authorized code. | 
**PreAuthorizedCode** | **string** | The raw opaque pre-authorized code for inclusion in the Credential Offer. | 

## Methods

### NewPreAuthorizedCodeResponse

`func NewPreAuthorizedCodeResponse(expiresAt string, preAuthorizedCode string, ) *PreAuthorizedCodeResponse`

NewPreAuthorizedCodeResponse instantiates a new PreAuthorizedCodeResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPreAuthorizedCodeResponseWithDefaults

`func NewPreAuthorizedCodeResponseWithDefaults() *PreAuthorizedCodeResponse`

NewPreAuthorizedCodeResponseWithDefaults instantiates a new PreAuthorizedCodeResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetExpiresAt

`func (o *PreAuthorizedCodeResponse) GetExpiresAt() string`

GetExpiresAt returns the ExpiresAt field if non-nil, zero value otherwise.

### GetExpiresAtOk

`func (o *PreAuthorizedCodeResponse) GetExpiresAtOk() (*string, bool)`

GetExpiresAtOk returns a tuple with the ExpiresAt field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpiresAt

`func (o *PreAuthorizedCodeResponse) SetExpiresAt(v string)`

SetExpiresAt sets ExpiresAt field to given value.


### GetPreAuthorizedCode

`func (o *PreAuthorizedCodeResponse) GetPreAuthorizedCode() string`

GetPreAuthorizedCode returns the PreAuthorizedCode field if non-nil, zero value otherwise.

### GetPreAuthorizedCodeOk

`func (o *PreAuthorizedCodeResponse) GetPreAuthorizedCodeOk() (*string, bool)`

GetPreAuthorizedCodeOk returns a tuple with the PreAuthorizedCode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPreAuthorizedCode

`func (o *PreAuthorizedCodeResponse) SetPreAuthorizedCode(v string)`

SetPreAuthorizedCode sets PreAuthorizedCode field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


