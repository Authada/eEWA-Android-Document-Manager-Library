//[document-manager](../../../index.md)/[eu.europa.ec.eudi.wallet.document](../index.md)/[DocumentManagerImpl](index.md)/[createIssuanceRequest](create-issuance-request.md)

# createIssuanceRequest

[androidJvm]\
open override fun [createIssuanceRequest](create-issuance-request.md)(docType: [String](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-string/index.html), hardwareBacked: [Boolean](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-boolean/index.html), attestationChallenge: [ByteArray](https://kotlinlang.org/api/latest/jvm/stdlib/kotlin/-byte-array/index.html)?): [CreateIssuanceRequestResult](../-create-issuance-request-result/index.md)

Create an issuance request for a given docType. The issuance request can be then used to issue the document from the issuer. The issuance request contains the certificate that must be sent to the issuer.

#### Return

[CreateIssuanceRequestResult.Success](../-create-issuance-request-result/-success/index.md) containing the issuance request if successful, [CreateIssuanceRequestResult.Failure](../-create-issuance-request-result/-failure/index.md) otherwise

#### Parameters

androidJvm

| | |
|---|---|
| docType | document's docType (example: &quot;eu.europa.ec.eudi.pid.1&quot;) |
| hardwareBacked | whether the document should be stored in hardware backed storage |
| attestationChallenge | optional attestationChallenge to check provided by the issuer |
