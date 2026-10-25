# PushAuthorizeResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ExpiresIn** | **int64** | The lifetime of the request URI in seconds. | 
**RequestUri** | **string** | The request URI corresponding to the authorization request posted. It is used as the &#x60;request_uri&#x60; parameter at the authorization endpoint. | 

## Methods

### NewPushAuthorizeResponse

`func NewPushAuthorizeResponse(expiresIn int64, requestUri string, ) *PushAuthorizeResponse`

NewPushAuthorizeResponse instantiates a new PushAuthorizeResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPushAuthorizeResponseWithDefaults

`func NewPushAuthorizeResponseWithDefaults() *PushAuthorizeResponse`

NewPushAuthorizeResponseWithDefaults instantiates a new PushAuthorizeResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetExpiresIn

`func (o *PushAuthorizeResponse) GetExpiresIn() int64`

GetExpiresIn returns the ExpiresIn field if non-nil, zero value otherwise.

### GetExpiresInOk

`func (o *PushAuthorizeResponse) GetExpiresInOk() (*int64, bool)`

GetExpiresInOk returns a tuple with the ExpiresIn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExpiresIn

`func (o *PushAuthorizeResponse) SetExpiresIn(v int64)`

SetExpiresIn sets ExpiresIn field to given value.


### GetRequestUri

`func (o *PushAuthorizeResponse) GetRequestUri() string`

GetRequestUri returns the RequestUri field if non-nil, zero value otherwise.

### GetRequestUriOk

`func (o *PushAuthorizeResponse) GetRequestUriOk() (*string, bool)`

GetRequestUriOk returns a tuple with the RequestUri field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRequestUri

`func (o *PushAuthorizeResponse) SetRequestUri(v string)`

SetRequestUri sets RequestUri field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


