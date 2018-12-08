using org.bouncycastle.asn1.cmp;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.asn1.test
{

	using TestCase = junit.framework.TestCase;
	using CAKeyUpdAnnContent = org.bouncycastle.asn1.cmp.CAKeyUpdAnnContent;
	using CMPCertificate = org.bouncycastle.asn1.cmp.CMPCertificate;
	using CRLAnnContent = org.bouncycastle.asn1.cmp.CRLAnnContent;
	using CertConfirmContent = org.bouncycastle.asn1.cmp.CertConfirmContent;
	using CertOrEncCert = org.bouncycastle.asn1.cmp.CertOrEncCert;
	using CertRepMessage = org.bouncycastle.asn1.cmp.CertRepMessage;
	using CertResponse = org.bouncycastle.asn1.cmp.CertResponse;
	using CertifiedKeyPair = org.bouncycastle.asn1.cmp.CertifiedKeyPair;
	using Challenge = org.bouncycastle.asn1.cmp.Challenge;
	using ErrorMsgContent = org.bouncycastle.asn1.cmp.ErrorMsgContent;
	using GenMsgContent = org.bouncycastle.asn1.cmp.GenMsgContent;
	using GenRepContent = org.bouncycastle.asn1.cmp.GenRepContent;
	using InfoTypeAndValue = org.bouncycastle.asn1.cmp.InfoTypeAndValue;
	using KeyRecRepContent = org.bouncycastle.asn1.cmp.KeyRecRepContent;
	using OOBCertHash = org.bouncycastle.asn1.cmp.OOBCertHash;
	using PBMParameter = org.bouncycastle.asn1.cmp.PBMParameter;
	using PKIBody = org.bouncycastle.asn1.cmp.PKIBody;
	using PKIConfirmContent = org.bouncycastle.asn1.cmp.PKIConfirmContent;
	using PKIFailureInfo = org.bouncycastle.asn1.cmp.PKIFailureInfo;
	using PKIFreeText = org.bouncycastle.asn1.cmp.PKIFreeText;
	using PKIHeader = org.bouncycastle.asn1.cmp.PKIHeader;
	using PKIMessage = org.bouncycastle.asn1.cmp.PKIMessage;
	using PKIMessages = org.bouncycastle.asn1.cmp.PKIMessages;
	using PKIStatus = org.bouncycastle.asn1.cmp.PKIStatus;
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using POPODecKeyChallContent = org.bouncycastle.asn1.cmp.POPODecKeyChallContent;
	using POPODecKeyRespContent = org.bouncycastle.asn1.cmp.POPODecKeyRespContent;
	using PollRepContent = org.bouncycastle.asn1.cmp.PollRepContent;
	using PollReqContent = org.bouncycastle.asn1.cmp.PollReqContent;
	using ProtectedPart = org.bouncycastle.asn1.cmp.ProtectedPart;
	using RevAnnContent = org.bouncycastle.asn1.cmp.RevAnnContent;
	using RevDetails = org.bouncycastle.asn1.cmp.RevDetails;
	using RevRepContent = org.bouncycastle.asn1.cmp.RevRepContent;
	using RevReqContent = org.bouncycastle.asn1.cmp.RevReqContent;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using Attributes = org.bouncycastle.asn1.cms.Attributes;
	using AuthEnvelopedData = org.bouncycastle.asn1.cms.AuthEnvelopedData;
	using AuthenticatedData = org.bouncycastle.asn1.cms.AuthenticatedData;
	using CompressedData = org.bouncycastle.asn1.cms.CompressedData;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using EncryptedContentInfo = org.bouncycastle.asn1.cms.EncryptedContentInfo;
	using EncryptedData = org.bouncycastle.asn1.cms.EncryptedData;
	using EnvelopedData = org.bouncycastle.asn1.cms.EnvelopedData;
	using Evidence = org.bouncycastle.asn1.cms.Evidence;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using KEKIdentifier = org.bouncycastle.asn1.cms.KEKIdentifier;
	using KEKRecipientInfo = org.bouncycastle.asn1.cms.KEKRecipientInfo;
	using KeyAgreeRecipientIdentifier = org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
	using KeyAgreeRecipientInfo = org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
	using KeyTransRecipientInfo = org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
	using MetaData = org.bouncycastle.asn1.cms.MetaData;
	using OriginatorIdentifierOrKey = org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
	using OriginatorInfo = org.bouncycastle.asn1.cms.OriginatorInfo;
	using OriginatorPublicKey = org.bouncycastle.asn1.cms.OriginatorPublicKey;
	using OtherKeyAttribute = org.bouncycastle.asn1.cms.OtherKeyAttribute;
	using OtherRecipientInfo = org.bouncycastle.asn1.cms.OtherRecipientInfo;
	using PasswordRecipientInfo = org.bouncycastle.asn1.cms.PasswordRecipientInfo;
	using RecipientEncryptedKey = org.bouncycastle.asn1.cms.RecipientEncryptedKey;
	using RecipientIdentifier = org.bouncycastle.asn1.cms.RecipientIdentifier;
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using RecipientKeyIdentifier = org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
	using SignerIdentifier = org.bouncycastle.asn1.cms.SignerIdentifier;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;
	using TimeStampAndCRL = org.bouncycastle.asn1.cms.TimeStampAndCRL;
	using TimeStampTokenEvidence = org.bouncycastle.asn1.cms.TimeStampTokenEvidence;
	using TimeStampedData = org.bouncycastle.asn1.cms.TimeStampedData;
	using MQVuserKeyingMaterial = org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
	using AttributeTypeAndValue = org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
	using CertId = org.bouncycastle.asn1.crmf.CertId;
	using CertReqMessages = org.bouncycastle.asn1.crmf.CertReqMessages;
	using CertReqMsg = org.bouncycastle.asn1.crmf.CertReqMsg;
	using CertRequest = org.bouncycastle.asn1.crmf.CertRequest;
	using CertTemplate = org.bouncycastle.asn1.crmf.CertTemplate;
	using Controls = org.bouncycastle.asn1.crmf.Controls;
	using EncKeyWithID = org.bouncycastle.asn1.crmf.EncKeyWithID;
	using EncryptedKey = org.bouncycastle.asn1.crmf.EncryptedKey;
	using EncryptedValue = org.bouncycastle.asn1.crmf.EncryptedValue;
	using OptionalValidity = org.bouncycastle.asn1.crmf.OptionalValidity;
	using PKIArchiveOptions = org.bouncycastle.asn1.crmf.PKIArchiveOptions;
	using PKIPublicationInfo = org.bouncycastle.asn1.crmf.PKIPublicationInfo;
	using PKMACValue = org.bouncycastle.asn1.crmf.PKMACValue;
	using POPOPrivKey = org.bouncycastle.asn1.crmf.POPOPrivKey;
	using POPOSigningKey = org.bouncycastle.asn1.crmf.POPOSigningKey;
	using POPOSigningKeyInput = org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
	using ProofOfPossession = org.bouncycastle.asn1.crmf.ProofOfPossession;
	using SinglePubInfo = org.bouncycastle.asn1.crmf.SinglePubInfo;
	using ECGOST3410ParamSetParameters = org.bouncycastle.asn1.cryptopro.ECGOST3410ParamSetParameters;
	using GOST28147Parameters = org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
	using GOST3410ParamSetParameters = org.bouncycastle.asn1.cryptopro.GOST3410ParamSetParameters;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using CVCertificate = org.bouncycastle.asn1.eac.CVCertificate;
	using CVCertificateRequest = org.bouncycastle.asn1.eac.CVCertificateRequest;
	using CertificateBody = org.bouncycastle.asn1.eac.CertificateBody;
	using PublicKeyDataObject = org.bouncycastle.asn1.eac.PublicKeyDataObject;
	using RSAPublicKey = org.bouncycastle.asn1.eac.RSAPublicKey;
	using UnsignedInteger = org.bouncycastle.asn1.eac.UnsignedInteger;
	using CommitmentTypeIndication = org.bouncycastle.asn1.esf.CommitmentTypeIndication;
	using CommitmentTypeQualifier = org.bouncycastle.asn1.esf.CommitmentTypeQualifier;
	using CompleteRevocationRefs = org.bouncycastle.asn1.esf.CompleteRevocationRefs;
	using CrlIdentifier = org.bouncycastle.asn1.esf.CrlIdentifier;
	using CrlListID = org.bouncycastle.asn1.esf.CrlListID;
	using CrlOcspRef = org.bouncycastle.asn1.esf.CrlOcspRef;
	using CrlValidatedID = org.bouncycastle.asn1.esf.CrlValidatedID;
	using OcspIdentifier = org.bouncycastle.asn1.esf.OcspIdentifier;
	using OcspListID = org.bouncycastle.asn1.esf.OcspListID;
	using OcspResponsesID = org.bouncycastle.asn1.esf.OcspResponsesID;
	using OtherHash = org.bouncycastle.asn1.esf.OtherHash;
	using OtherHashAlgAndValue = org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
	using OtherRevRefs = org.bouncycastle.asn1.esf.OtherRevRefs;
	using OtherRevVals = org.bouncycastle.asn1.esf.OtherRevVals;
	using RevocationValues = org.bouncycastle.asn1.esf.RevocationValues;
	using SPUserNotice = org.bouncycastle.asn1.esf.SPUserNotice;
	using SPuri = org.bouncycastle.asn1.esf.SPuri;
	using SigPolicyQualifierInfo = org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
	using SigPolicyQualifiers = org.bouncycastle.asn1.esf.SigPolicyQualifiers;
	using SignaturePolicyId = org.bouncycastle.asn1.esf.SignaturePolicyId;
	using SignaturePolicyIdentifier = org.bouncycastle.asn1.esf.SignaturePolicyIdentifier;
	using SignerAttribute = org.bouncycastle.asn1.esf.SignerAttribute;
	using SignerLocation = org.bouncycastle.asn1.esf.SignerLocation;
	using ContentHints = org.bouncycastle.asn1.ess.ContentHints;
	using ContentIdentifier = org.bouncycastle.asn1.ess.ContentIdentifier;
	using ESSCertID = org.bouncycastle.asn1.ess.ESSCertID;
	using ESSCertIDv2 = org.bouncycastle.asn1.ess.ESSCertIDv2;
	using OtherCertID = org.bouncycastle.asn1.ess.OtherCertID;
	using OtherSigningCertificate = org.bouncycastle.asn1.ess.OtherSigningCertificate;
	using SigningCertificate = org.bouncycastle.asn1.ess.SigningCertificate;
	using SigningCertificateV2 = org.bouncycastle.asn1.ess.SigningCertificateV2;
	using CscaMasterList = org.bouncycastle.asn1.icao.CscaMasterList;
	using DataGroupHash = org.bouncycastle.asn1.icao.DataGroupHash;
	using LDSSecurityObject = org.bouncycastle.asn1.icao.LDSSecurityObject;
	using LDSVersionInfo = org.bouncycastle.asn1.icao.LDSVersionInfo;
	using CertHash = org.bouncycastle.asn1.isismtt.ocsp.CertHash;
	using RequestedCertificate = org.bouncycastle.asn1.isismtt.ocsp.RequestedCertificate;
	using AdditionalInformationSyntax = org.bouncycastle.asn1.isismtt.x509.AdditionalInformationSyntax;
	using AdmissionSyntax = org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax;
	using Admissions = org.bouncycastle.asn1.isismtt.x509.Admissions;
	using DeclarationOfMajority = org.bouncycastle.asn1.isismtt.x509.DeclarationOfMajority;
	using MonetaryLimit = org.bouncycastle.asn1.isismtt.x509.MonetaryLimit;
	using NamingAuthority = org.bouncycastle.asn1.isismtt.x509.NamingAuthority;
	using ProcurationSyntax = org.bouncycastle.asn1.isismtt.x509.ProcurationSyntax;
	using ProfessionInfo = org.bouncycastle.asn1.isismtt.x509.ProfessionInfo;
	using Restriction = org.bouncycastle.asn1.isismtt.x509.Restriction;
	using CAST5CBCParameters = org.bouncycastle.asn1.misc.CAST5CBCParameters;
	using IDEACBCPar = org.bouncycastle.asn1.misc.IDEACBCPar;
	using PublicKeyAndChallenge = org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
	using BasicOCSPResponse = org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
	using CertID = org.bouncycastle.asn1.ocsp.CertID;
	using CertStatus = org.bouncycastle.asn1.ocsp.CertStatus;
	using CrlID = org.bouncycastle.asn1.ocsp.CrlID;
	using OCSPRequest = org.bouncycastle.asn1.ocsp.OCSPRequest;
	using OCSPResponse = org.bouncycastle.asn1.ocsp.OCSPResponse;
	using OCSPResponseStatus = org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
	using Request = org.bouncycastle.asn1.ocsp.Request;
	using ResponderID = org.bouncycastle.asn1.ocsp.ResponderID;
	using ResponseBytes = org.bouncycastle.asn1.ocsp.ResponseBytes;
	using ResponseData = org.bouncycastle.asn1.ocsp.ResponseData;
	using RevokedInfo = org.bouncycastle.asn1.ocsp.RevokedInfo;
	using Signature = org.bouncycastle.asn1.ocsp.Signature;
	using SingleResponse = org.bouncycastle.asn1.ocsp.SingleResponse;
	using TBSRequest = org.bouncycastle.asn1.ocsp.TBSRequest;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AuthenticatedSafe = org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
	using CertificationRequest = org.bouncycastle.asn1.pkcs.CertificationRequest;
	using CertificationRequestInfo = org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using MacData = org.bouncycastle.asn1.pkcs.MacData;
	using PBEParameter = org.bouncycastle.asn1.pkcs.PBEParameter;
	using PBES2Parameters = org.bouncycastle.asn1.pkcs.PBES2Parameters;
	using PBKDF2Params = org.bouncycastle.asn1.pkcs.PBKDF2Params;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using Pfx = org.bouncycastle.asn1.pkcs.Pfx;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using RC2CBCParameter = org.bouncycastle.asn1.pkcs.RC2CBCParameter;
	using RSAESOAEPparams = org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
	using RSAPrivateKey = org.bouncycastle.asn1.pkcs.RSAPrivateKey;
	using RSASSAPSSparams = org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
	using SafeBag = org.bouncycastle.asn1.pkcs.SafeBag;
	using SignedData = org.bouncycastle.asn1.pkcs.SignedData;
	using ECPrivateKey = org.bouncycastle.asn1.sec.ECPrivateKey;
	using SMIMECapabilities = org.bouncycastle.asn1.smime.SMIMECapabilities;
	using SMIMECapability = org.bouncycastle.asn1.smime.SMIMECapability;
	using Accuracy = org.bouncycastle.asn1.tsp.Accuracy;
	using MessageImprint = org.bouncycastle.asn1.tsp.MessageImprint;
	using TSTInfo = org.bouncycastle.asn1.tsp.TSTInfo;
	using TimeStampReq = org.bouncycastle.asn1.tsp.TimeStampReq;
	using TimeStampResp = org.bouncycastle.asn1.tsp.TimeStampResp;
	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;
	using RDN = org.bouncycastle.asn1.x500.RDN;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AccessDescription = org.bouncycastle.asn1.x509.AccessDescription;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AttCertIssuer = org.bouncycastle.asn1.x509.AttCertIssuer;
	using AttCertValidityPeriod = org.bouncycastle.asn1.x509.AttCertValidityPeriod;
	using AttributeCertificate = org.bouncycastle.asn1.x509.AttributeCertificate;
	using AttributeCertificateInfo = org.bouncycastle.asn1.x509.AttributeCertificateInfo;
	using AuthorityInformationAccess = org.bouncycastle.asn1.x509.AuthorityInformationAccess;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using CRLNumber = org.bouncycastle.asn1.x509.CRLNumber;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using CertificatePair = org.bouncycastle.asn1.x509.CertificatePair;
	using CertificatePolicies = org.bouncycastle.asn1.x509.CertificatePolicies;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using DisplayText = org.bouncycastle.asn1.x509.DisplayText;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using ExtendedKeyUsage = org.bouncycastle.asn1.x509.ExtendedKeyUsage;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using GeneralSubtree = org.bouncycastle.asn1.x509.GeneralSubtree;
	using Holder = org.bouncycastle.asn1.x509.Holder;
	using IetfAttrSyntax = org.bouncycastle.asn1.x509.IetfAttrSyntax;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using NameConstraints = org.bouncycastle.asn1.x509.NameConstraints;
	using NoticeReference = org.bouncycastle.asn1.x509.NoticeReference;
	using ObjectDigestInfo = org.bouncycastle.asn1.x509.ObjectDigestInfo;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using PolicyMappings = org.bouncycastle.asn1.x509.PolicyMappings;
	using PolicyQualifierInfo = org.bouncycastle.asn1.x509.PolicyQualifierInfo;
	using PrivateKeyUsagePeriod = org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
	using RoleSyntax = org.bouncycastle.asn1.x509.RoleSyntax;
	using SubjectDirectoryAttributes = org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using TBSCertificateStructure = org.bouncycastle.asn1.x509.TBSCertificateStructure;
	using Target = org.bouncycastle.asn1.x509.Target;
	using TargetInformation = org.bouncycastle.asn1.x509.TargetInformation;
	using Targets = org.bouncycastle.asn1.x509.Targets;
	using Time = org.bouncycastle.asn1.x509.Time;
	using UserNotice = org.bouncycastle.asn1.x509.UserNotice;
	using V2Form = org.bouncycastle.asn1.x509.V2Form;
	using X509CertificateStructure = org.bouncycastle.asn1.x509.X509CertificateStructure;
	using X509Extensions = org.bouncycastle.asn1.x509.X509Extensions;
	using BiometricData = org.bouncycastle.asn1.x509.qualified.BiometricData;
	using Iso4217CurrencyCode = org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
	using MonetaryValue = org.bouncycastle.asn1.x509.qualified.MonetaryValue;
	using QCStatement = org.bouncycastle.asn1.x509.qualified.QCStatement;
	using SemanticsInformation = org.bouncycastle.asn1.x509.qualified.SemanticsInformation;
	using TypeOfBiometricData = org.bouncycastle.asn1.x509.qualified.TypeOfBiometricData;
	using NameOrPseudonym = org.bouncycastle.asn1.x509.sigi.NameOrPseudonym;
	using PersonalData = org.bouncycastle.asn1.x509.sigi.PersonalData;
	using DHDomainParameters = org.bouncycastle.asn1.x9.DHDomainParameters;
	using DHPublicKey = org.bouncycastle.asn1.x9.DHPublicKey;
	using DHValidationParms = org.bouncycastle.asn1.x9.DHValidationParms;
	using X962Parameters = org.bouncycastle.asn1.x9.X962Parameters;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using Integers = org.bouncycastle.util.Integers;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	public class GetInstanceTest : TestCase
	{
		public static byte[] attrCert = Base64.decode("MIIHQDCCBqkCAQEwgZChgY2kgYowgYcxHDAaBgkqhkiG9w0BCQEWDW1sb3JjaEB2" + "dC5lZHUxHjAcBgNVBAMTFU1hcmt1cyBMb3JjaCAobWxvcmNoKTEbMBkGA1UECxMS" + "VmlyZ2luaWEgVGVjaCBVc2VyMRAwDgYDVQQLEwdDbGFzcyAyMQswCQYDVQQKEwJ2" + "dDELMAkGA1UEBhMCVVMwgYmkgYYwgYMxGzAZBgkqhkiG9w0BCQEWDHNzaGFoQHZ0" + "LmVkdTEbMBkGA1UEAxMSU3VtaXQgU2hhaCAoc3NoYWgpMRswGQYDVQQLExJWaXJn" + "aW5pYSBUZWNoIFVzZXIxEDAOBgNVBAsTB0NsYXNzIDExCzAJBgNVBAoTAnZ0MQsw" + "CQYDVQQGEwJVUzANBgkqhkiG9w0BAQQFAAIBBTAiGA8yMDAzMDcxODE2MDgwMloY" + "DzIwMDMwNzI1MTYwODAyWjCCBU0wggVJBgorBgEEAbRoCAEBMYIFORaCBTU8UnVs" + "ZSBSdWxlSWQ9IkZpbGUtUHJpdmlsZWdlLVJ1bGUiIEVmZmVjdD0iUGVybWl0Ij4K" + "IDxUYXJnZXQ+CiAgPFN1YmplY3RzPgogICA8U3ViamVjdD4KICAgIDxTdWJqZWN0" + "TWF0Y2ggTWF0Y2hJZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5j" + "dGlvbjpzdHJpbmctZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlw" + "ZT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjc3RyaW5nIj4KICAg" + "ICAgIENOPU1hcmt1cyBMb3JjaDwvQXR0cmlidXRlVmFsdWU+CiAgICAgPFN1Ympl" + "Y3RBdHRyaWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFt" + "ZXM6dGM6eGFjbWw6MS4wOnN1YmplY3Q6c3ViamVjdC1pZCIgRGF0YVR5cGU9Imh0" + "dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hI3N0cmluZyIgLz4gCiAgICA8" + "L1N1YmplY3RNYXRjaD4KICAgPC9TdWJqZWN0PgogIDwvU3ViamVjdHM+CiAgPFJl" + "c291cmNlcz4KICAgPFJlc291cmNlPgogICAgPFJlc291cmNlTWF0Y2ggTWF0Y2hJ" + "ZD0idXJuOm9hc2lzOm5hbWVzOnRjOnhhY21sOjEuMDpmdW5jdGlvbjpzdHJpbmct" + "ZXF1YWwiPgogICAgIDxBdHRyaWJ1dGVWYWx1ZSBEYXRhVHlwZT0iaHR0cDovL3d3" + "dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIj4KICAgICAgaHR0cDovL3p1" + "bmkuY3MudnQuZWR1PC9BdHRyaWJ1dGVWYWx1ZT4KICAgICA8UmVzb3VyY2VBdHRy" + "aWJ1dGVEZXNpZ25hdG9yIEF0dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6" + "eGFjbWw6MS4wOnJlc291cmNlOnJlc291cmNlLWlkIiBEYXRhVHlwZT0iaHR0cDov" + "L3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEjYW55VVJJIiAvPiAKICAgIDwvUmVz" + "b3VyY2VNYXRjaD4KICAgPC9SZXNvdXJjZT4KICA8L1Jlc291cmNlcz4KICA8QWN0" + "aW9ucz4KICAgPEFjdGlvbj4KICAgIDxBY3Rpb25NYXRjaCBNYXRjaElkPSJ1cm46" + "b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmZ1bmN0aW9uOnN0cmluZy1lcXVhbCI+" + "CiAgICAgPEF0dHJpYnV0ZVZhbHVlIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9y" + "Zy8yMDAxL1hNTFNjaGVtYSNzdHJpbmciPgpEZWxlZ2F0ZSBBY2Nlc3MgICAgIDwv" + "QXR0cmlidXRlVmFsdWU+CgkgIDxBY3Rpb25BdHRyaWJ1dGVEZXNpZ25hdG9yIEF0" + "dHJpYnV0ZUlkPSJ1cm46b2FzaXM6bmFtZXM6dGM6eGFjbWw6MS4wOmFjdGlvbjph" + "Y3Rpb24taWQiIERhdGFUeXBlPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNj" + "aGVtYSNzdHJpbmciIC8+IAogICAgPC9BY3Rpb25NYXRjaD4KICAgPC9BY3Rpb24+" + "CiAgPC9BY3Rpb25zPgogPC9UYXJnZXQ+CjwvUnVsZT4KMA0GCSqGSIb3DQEBBAUA" + "A4GBAGiJSM48XsY90HlYxGmGVSmNR6ZW2As+bot3KAfiCIkUIOAqhcphBS23egTr" + "6asYwy151HshbPNYz+Cgeqs45KkVzh7bL/0e1r8sDVIaaGIkjHK3CqBABnfSayr3" + "Rd1yBoDdEv8Qb+3eEPH6ab9021AsLEnJ6LWTmybbOpMNZ3tv");

		internal byte[] cert1 = Base64.decode("MIIDXjCCAsegAwIBAgIBBzANBgkqhkiG9w0BAQQFADCBtzELMAkGA1UEBhMCQVUx" + "ETAPBgNVBAgTCFZpY3RvcmlhMRgwFgYDVQQHEw9Tb3V0aCBNZWxib3VybmUxGjAY" + "BgNVBAoTEUNvbm5lY3QgNCBQdHkgTHRkMR4wHAYDVQQLExVDZXJ0aWZpY2F0ZSBB" + "dXRob3JpdHkxFTATBgNVBAMTDENvbm5lY3QgNCBDQTEoMCYGCSqGSIb3DQEJARYZ" + "d2VibWFzdGVyQGNvbm5lY3Q0LmNvbS5hdTAeFw0wMDA2MDIwNzU2MjFaFw0wMTA2" + "MDIwNzU2MjFaMIG4MQswCQYDVQQGEwJBVTERMA8GA1UECBMIVmljdG9yaWExGDAW" + "BgNVBAcTD1NvdXRoIE1lbGJvdXJuZTEaMBgGA1UEChMRQ29ubmVjdCA0IFB0eSBM" + "dGQxFzAVBgNVBAsTDldlYnNlcnZlciBUZWFtMR0wGwYDVQQDExR3d3cyLmNvbm5l" + "Y3Q0LmNvbS5hdTEoMCYGCSqGSIb3DQEJARYZd2VibWFzdGVyQGNvbm5lY3Q0LmNv" + "bS5hdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEArvDxclKAhyv7Q/Wmr2re" + "Gw4XL9Cnh9e+6VgWy2AWNy/MVeXdlxzd7QAuc1eOWQkGQEiLPy5XQtTY+sBUJ3AO" + "Rvd2fEVJIcjf29ey7bYua9J/vz5MG2KYo9/WCHIwqD9mmG9g0xLcfwq/s8ZJBswE" + "7sb85VU+h94PTvsWOsWuKaECAwEAAaN3MHUwJAYDVR0RBB0wG4EZd2VibWFzdGVy" + "QGNvbm5lY3Q0LmNvbS5hdTA6BglghkgBhvhCAQ0ELRYrbW9kX3NzbCBnZW5lcmF0" + "ZWQgY3VzdG9tIHNlcnZlciBjZXJ0aWZpY2F0ZTARBglghkgBhvhCAQEEBAMCBkAw" + "DQYJKoZIhvcNAQEEBQADgYEAotccfKpwSsIxM1Hae8DR7M/Rw8dg/RqOWx45HNVL" + "iBS4/3N/TO195yeQKbfmzbAA2jbPVvIvGgTxPgO1MP4ZgvgRhasaa0qCJCkWvpM4" + "yQf33vOiYQbpv4rTwzU8AmRlBG45WdjyNIigGV+oRc61aKCTnLq7zB8N3z1TF/bF" + "5/8=");

		private byte[] v2CertList = Base64.decode("MIICjTCCAfowDQYJKoZIhvcNAQECBQAwXzELMAkGA1UEBhMCVVMxIDAeBgNVBAoT" + "F1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYDVQQLEyVTZWN1cmUgU2VydmVy" + "IENlcnRpZmljYXRpb24gQXV0aG9yaXR5Fw05NTA1MDIwMjEyMjZaFw05NTA2MDEw" + "MDAxNDlaMIIBaDAWAgUCQQAABBcNOTUwMjAxMTcyNDI2WjAWAgUCQQAACRcNOTUw" + "MjEwMDIxNjM5WjAWAgUCQQAADxcNOTUwMjI0MDAxMjQ5WjAWAgUCQQAADBcNOTUw" + "MjI1MDA0NjQ0WjAWAgUCQQAAGxcNOTUwMzEzMTg0MDQ5WjAWAgUCQQAAFhcNOTUw" + "MzE1MTkxNjU0WjAWAgUCQQAAGhcNOTUwMzE1MTk0MDQxWjAWAgUCQQAAHxcNOTUw" + "MzI0MTk0NDMzWjAWAgUCcgAABRcNOTUwMzI5MjAwNzExWjAWAgUCcgAAERcNOTUw" + "MzMwMDIzNDI2WjAWAgUCQQAAIBcNOTUwNDA3MDExMzIxWjAWAgUCcgAAHhcNOTUw" + "NDA4MDAwMjU5WjAWAgUCcgAAQRcNOTUwNDI4MTcxNzI0WjAWAgUCcgAAOBcNOTUw" + "NDI4MTcyNzIxWjAWAgUCcgAATBcNOTUwNTAyMDIxMjI2WjANBgkqhkiG9w0BAQIF" + "AAN+AHqOEJXSDejYy0UwxxrH/9+N2z5xu/if0J6qQmK92W0hW158wpJg+ovV3+wQ" + "wvIEPRL2rocL0tKfAsVq1IawSJzSNgxG0lrcla3MrJBnZ4GaZDu4FutZh72MR3Gt" + "JaAL3iTJHJD55kK2D/VoyY1djlsPuNh6AEgdVwFAyp0v");

		private static readonly object[] NULL_ARGS = new object[] {null};

		private void doFullGetInstanceTest(Class clazz, ASN1Object o1)
		{
			Method m;

			try
			{
				m = clazz.getMethod("getInstance", typeof(object));
			}
			catch (NoSuchMethodException)
			{
				fail("no getInstance method found");
				return;
			}

			ASN1Object o2 = (ASN1Object)m.invoke(clazz, NULL_ARGS);
			if (o2 != null)
			{
				fail(clazz.getName() + " null failed");
			}

			o2 = (ASN1Object)m.invoke(clazz, o1);

			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " equality failed");
			}

			o2 = (ASN1Object)m.invoke(clazz, o1.getEncoded());
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " encoded equality failed");
			}

			o2 = (ASN1Object)m.invoke(clazz, o1.toASN1Primitive());
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " sequence equality failed");
			}

			try
			{
				m = clazz.getMethod("getInstance", typeof(ASN1TaggedObject), Boolean.TYPE);
			}
			catch (NoSuchMethodException)
			{
				return;
			}

			ASN1TaggedObject t = new DERTaggedObject(true, 0, o1);
			o2 = (ASN1Object)m.invoke(clazz, t, true);
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " tag equality failed");
			}

			t = new DERTaggedObject(true, 0, o1.toASN1Primitive());
			o2 = (ASN1Object)m.invoke(clazz, t, true);
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " tag equality failed");
			}

			t = ASN1TaggedObject.getInstance(t.getEncoded());
			o2 = (ASN1Object)m.invoke(clazz, t, true);
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " tag equality failed");
			}

			t = new DERTaggedObject(false, 0, o1);
			o2 = (ASN1Object)m.invoke(clazz, t, false);
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " tag equality failed");
			}

			t = new DERTaggedObject(false, 0, o1.toASN1Primitive());
			o2 = (ASN1Object)m.invoke(clazz, t, false);
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " tag equality failed");
			}

			t = ASN1TaggedObject.getInstance(t.getEncoded());
			o2 = (ASN1Object)m.invoke(clazz, t, false);
			if (!o1.Equals(o2) || !clazz.isInstance(o2))
			{
				fail(clazz.getName() + " tag equality failed");
			}
		}

		public virtual void testGetInstance()
		{
			doFullGetInstanceTest(typeof(DERPrintableString), new DERPrintableString("hello world"));
			doFullGetInstanceTest(typeof(DERBMPString), new DERBMPString("hello world"));
			doFullGetInstanceTest(typeof(DERUTF8String), new DERUTF8String("hello world"));
			doFullGetInstanceTest(typeof(DERUniversalString), new DERUniversalString(new byte[20]));
			doFullGetInstanceTest(typeof(DERIA5String), new DERIA5String("hello world"));
			doFullGetInstanceTest(typeof(DERGeneralString), new DERGeneralString("hello world"));
			doFullGetInstanceTest(typeof(DERNumericString), new DERNumericString("hello world"));
			doFullGetInstanceTest(typeof(DERNumericString), new DERNumericString("99999", true));
			doFullGetInstanceTest(typeof(DERT61String), new DERT61String("hello world"));
			doFullGetInstanceTest(typeof(DERVisibleString), new DERVisibleString("hello world"));

			doFullGetInstanceTest(typeof(ASN1Integer), new ASN1Integer(1));
			doFullGetInstanceTest(typeof(ASN1GeneralizedTime), new ASN1GeneralizedTime(DateTime.Now));
			doFullGetInstanceTest(typeof(ASN1UTCTime), new ASN1UTCTime(DateTime.Now));
			doFullGetInstanceTest(typeof(ASN1Enumerated), new ASN1Enumerated(1));

			CMPCertificate cmpCert = new CMPCertificate(Certificate.getInstance(cert1));
			CertificateList crl = CertificateList.getInstance(v2CertList);
			AttributeCertificate attributeCert = AttributeCertificate.getInstance(attrCert);

			doFullGetInstanceTest(typeof(CAKeyUpdAnnContent), new CAKeyUpdAnnContent(cmpCert, cmpCert, cmpCert));

			CertConfirmContent.getInstance(null);
			CertifiedKeyPair.getInstance(null);
			CertOrEncCert.getInstance(null);
			CertRepMessage.getInstance(null);
			doFullGetInstanceTest(typeof(CertResponse), new CertResponse(new ASN1Integer(1), new PKIStatusInfo(PKIStatus.granted)));
			doFullGetInstanceTest(typeof(CertStatus), new CertStatus(new byte[10], BigInteger.valueOf(1), new PKIStatusInfo(PKIStatus.granted)));
			doFullGetInstanceTest(typeof(Challenge), new Challenge(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE), new byte[10], new byte[10]));

			doFullGetInstanceTest(typeof(CMPCertificate), cmpCert);
			doFullGetInstanceTest(typeof(CRLAnnContent), new CRLAnnContent(crl));
			doFullGetInstanceTest(typeof(ErrorMsgContent), new ErrorMsgContent(new PKIStatusInfo(PKIStatus.granted), new ASN1Integer(1), new PKIFreeText("fred")));
			GenMsgContent.getInstance(null);
			GenRepContent.getInstance(null);
			InfoTypeAndValue.getInstance(null);
			KeyRecRepContent.getInstance(null);
			OOBCertHash.getInstance(null);
			PBMParameter.getInstance(null);
			PKIBody.getInstance(null);
			PKIConfirmContent.getInstance(null);
			PKIFreeText.getInstance(null);
			doFullGetInstanceTest(typeof(PKIFreeText), new PKIFreeText("hello world"));
			doFullGetInstanceTest(typeof(PKIFreeText), new PKIFreeText(new string[]{"hello", "world"}));
			doFullGetInstanceTest(typeof(PKIFreeText), new PKIFreeText(new DERUTF8String[]
			{
				new DERUTF8String("hello"),
				new DERUTF8String("world")
			}));
			PKIHeader.getInstance(null);
			PKIMessage.getInstance(null);
			PKIMessages.getInstance(null);
			doFullGetInstanceTest(typeof(PKIStatusInfo), new PKIStatusInfo(PKIStatus.rejection, new PKIFreeText("hello world"), new PKIFailureInfo(PKIFailureInfo.badAlg)));
			doFullGetInstanceTest(typeof(PKIStatusInfo), new PKIStatusInfo(PKIStatus.granted, new PKIFreeText("hello world")));
			PKIStatus.getInstance(null);
			PollRepContent.getInstance(null);
			PollReqContent.getInstance(null);
			POPODecKeyChallContent.getInstance(null);
			POPODecKeyRespContent.getInstance(null);
			ProtectedPart.getInstance(null);
			RevAnnContent.getInstance(null);
			RevDetails.getInstance(null);
			RevRepContent.getInstance(null);
			RevReqContent.getInstance(null);
			Attribute.getInstance(null);
			Attributes.getInstance(null);
			AuthenticatedData.getInstance(null);
			AuthenticatedData.getInstance(null);
			AuthEnvelopedData.getInstance(null);
			AuthEnvelopedData.getInstance(null);
			CompressedData.getInstance(null);
			CompressedData.getInstance(null);
			ContentInfo.getInstance(null);
			EncryptedContentInfo.getInstance(null);
			EncryptedData.getInstance(null);
			EnvelopedData.getInstance(null);
			EnvelopedData.getInstance(null);
			Evidence.getInstance(null);
			IssuerAndSerialNumber.getInstance(null);
			KEKIdentifier.getInstance(null);
			KEKIdentifier.getInstance(null);
			KEKRecipientInfo.getInstance(null);
			KEKRecipientInfo.getInstance(null);
			KeyAgreeRecipientIdentifier.getInstance(null);
			KeyAgreeRecipientIdentifier.getInstance(null);
			KeyAgreeRecipientInfo.getInstance(null);
			KeyAgreeRecipientInfo.getInstance(null);
			KeyTransRecipientInfo.getInstance(null);
			MetaData.getInstance(null);
			OriginatorIdentifierOrKey.getInstance(null);
			OriginatorIdentifierOrKey.getInstance(null);
			OriginatorInfo.getInstance(null);
			OriginatorInfo.getInstance(null);
			OriginatorPublicKey.getInstance(null);
			OriginatorPublicKey.getInstance(null);
			OtherKeyAttribute.getInstance(null);
			OtherRecipientInfo.getInstance(null);
			OtherRecipientInfo.getInstance(null);
			PasswordRecipientInfo.getInstance(null);
			PasswordRecipientInfo.getInstance(null);
			RecipientEncryptedKey.getInstance(null);
			RecipientIdentifier.getInstance(null);
			RecipientInfo.getInstance(null);
			RecipientKeyIdentifier.getInstance(null);
			RecipientKeyIdentifier.getInstance(null);
			SignedData.getInstance(null);
			SignerIdentifier.getInstance(null);
			SignerInfo.getInstance(null);
			Time.getInstance(null);
			Time.getInstance(null);
			TimeStampAndCRL.getInstance(null);
			TimeStampedData.getInstance(null);
			TimeStampTokenEvidence.getInstance(null);
			AttributeTypeAndValue.getInstance(null);

			doFullGetInstanceTest(typeof(CertId), new CertId(new GeneralName(new X500Name("CN=Test")), BigInteger.valueOf(1)));


			CertReqMessages.getInstance(null);
			CertReqMsg.getInstance(null);
			CertRequest.getInstance(null);
			CertTemplate.getInstance(null);
			Controls.getInstance(null);
			EncKeyWithID.getInstance(null);
			EncryptedKey.getInstance(null);
			EncryptedValue.getInstance(null);
			OptionalValidity.getInstance(null);
			PKIArchiveOptions.getInstance(null);
			PKIPublicationInfo.getInstance(null);
			PKMACValue.getInstance(null);
			PKMACValue.getInstance(null);
			POPOPrivKey.getInstance(null);
			POPOSigningKeyInput.getInstance(null);
			POPOSigningKey.getInstance(null);
			POPOSigningKey.getInstance(null);
			ProofOfPossession.getInstance(null);
			SinglePubInfo.getInstance(null);
			ECGOST3410ParamSetParameters.getInstance(null);
			ECGOST3410ParamSetParameters.getInstance(null);
			GOST28147Parameters.getInstance(null);
			GOST28147Parameters.getInstance(null);
			GOST3410ParamSetParameters.getInstance(null);
			GOST3410ParamSetParameters.getInstance(null);
			GOST3410PublicKeyAlgParameters.getInstance(null);
			GOST3410PublicKeyAlgParameters.getInstance(null);
			CertificateBody.getInstance(null);
			CVCertificate.getInstance(null);
			CVCertificateRequest.getInstance(null);
			PublicKeyDataObject.getInstance(null);
			UnsignedInteger.getInstance(null);
			CommitmentTypeIndication.getInstance(null);
			CommitmentTypeQualifier.getInstance(null);

			OcspIdentifier ocspIdentifier = new OcspIdentifier(new ResponderID(new X500Name("CN=Test")), new ASN1GeneralizedTime(DateTime.Now));
			CrlListID crlListID = new CrlListID(new CrlValidatedID[]{new CrlValidatedID(new OtherHash(new byte[20]))});
			OcspListID ocspListID = new OcspListID(new OcspResponsesID[] {new OcspResponsesID(ocspIdentifier)});
			OtherRevRefs otherRevRefs = new OtherRevRefs(new ASN1ObjectIdentifier("1.2.1"), new DERSequence());
			OtherRevVals otherRevVals = new OtherRevVals(new ASN1ObjectIdentifier("1.2.1"), new DERSequence());
			CrlOcspRef crlOcspRef = new CrlOcspRef(crlListID, ocspListID, otherRevRefs);
			doFullGetInstanceTest(typeof(CompleteRevocationRefs), new CompleteRevocationRefs(new CrlOcspRef[]{crlOcspRef, crlOcspRef}));

			doFullGetInstanceTest(typeof(CrlIdentifier), new CrlIdentifier(new X500Name("CN=Test"), new ASN1UTCTime(DateTime.Now), BigInteger.valueOf(1)));


			doFullGetInstanceTest(typeof(CrlListID), crlListID);
			doFullGetInstanceTest(typeof(CrlOcspRef), crlOcspRef);
			doFullGetInstanceTest(typeof(CrlValidatedID), new CrlValidatedID(new OtherHash(new byte[20])));
			doFullGetInstanceTest(typeof(OcspIdentifier), ocspIdentifier);
			doFullGetInstanceTest(typeof(OcspListID), ocspListID);
			doFullGetInstanceTest(typeof(OcspResponsesID), new OcspResponsesID(ocspIdentifier));

			OtherHashAlgAndValue otherHashAlgAndValue = new OtherHashAlgAndValue(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[10]));
			doFullGetInstanceTest(typeof(OtherHashAlgAndValue), otherHashAlgAndValue);
			OtherHash.getInstance(null);
			doFullGetInstanceTest(typeof(OtherRevRefs), otherRevRefs);
			doFullGetInstanceTest(typeof(OtherRevVals), otherRevVals);
			doFullGetInstanceTest(typeof(RevocationValues), new RevocationValues(new CertificateList[]{crl}, null, otherRevVals));

			SignaturePolicyId signaturePolicyId = new SignaturePolicyId(new ASN1ObjectIdentifier("1.2.1"), otherHashAlgAndValue);
			doFullGetInstanceTest(typeof(SignaturePolicyIdentifier), new SignaturePolicyIdentifier());
			doFullGetInstanceTest(typeof(SignaturePolicyIdentifier), new SignaturePolicyIdentifier(signaturePolicyId));
			doFullGetInstanceTest(typeof(SignaturePolicyId), signaturePolicyId);
			doFullGetInstanceTest(typeof(SignerAttribute), new SignerAttribute(new Attribute[]{new Attribute(new ASN1ObjectIdentifier("1.2.1"), new DERSet())}));
			doFullGetInstanceTest(typeof(SignerAttribute), new SignerAttribute(attributeCert));

			ASN1EncodableVector postalAddr = new ASN1EncodableVector();

			postalAddr.add(new DERUTF8String("line 1"));
			postalAddr.add(new DERUTF8String("line 2"));

			doFullGetInstanceTest(typeof(SignerLocation), new SignerLocation(new DERUTF8String("AU"), new DERUTF8String("Melbourne"), new DERSequence(postalAddr)));
			doFullGetInstanceTest(typeof(SigPolicyQualifierInfo), new SigPolicyQualifierInfo(new ASN1ObjectIdentifier("1.2.1"), new DERSequence()));
			SigPolicyQualifiers.getInstance(null);
			SPuri.getInstance(null);
			Vector v = new Vector();

			v.add(Integers.valueOf(1));
			v.add(BigInteger.valueOf(2));
			NoticeReference noticeReference = new NoticeReference("BC", v);
			doFullGetInstanceTest(typeof(SPUserNotice), new SPUserNotice(noticeReference, new DisplayText("hello world")));
			ContentHints.getInstance(null);
			ContentIdentifier.getInstance(null);
			ESSCertID.getInstance(null);
			ESSCertIDv2.getInstance(null);
			OtherCertID.getInstance(null);
			OtherSigningCertificate.getInstance(null);
			SigningCertificate.getInstance(null);
			SigningCertificateV2.getInstance(null);
			CscaMasterList.getInstance(null);
			DataGroupHash.getInstance(null);
			LDSSecurityObject.getInstance(null);
			LDSVersionInfo.getInstance(null);
			CAST5CBCParameters.getInstance(null);
			IDEACBCPar.getInstance(null);
			PublicKeyAndChallenge.getInstance(null);
			BasicOCSPResponse.getInstance(null);
			BasicOCSPResponse.getInstance(null);

			doFullGetInstanceTest(typeof(CertID), new CertID(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1, DERNull.INSTANCE), new DEROctetString(new byte[1]), new DEROctetString(new byte[1]), new ASN1Integer(1)));

			CertStatus.getInstance(null);
			CertStatus.getInstance(null);
			CrlID.getInstance(null);
			OCSPRequest.getInstance(null);
			OCSPRequest.getInstance(null);
			OCSPResponse.getInstance(null);
			OCSPResponse.getInstance(null);
			OCSPResponseStatus.getInstance(null);
			Request.getInstance(null);
			Request.getInstance(null);
			ResponderID.getInstance(null);
			ResponderID.getInstance(null);
			ResponseBytes.getInstance(null);
			ResponseBytes.getInstance(null);
			ResponseData.getInstance(null);
			ResponseData.getInstance(null);
			RevokedInfo.getInstance(null);
			RevokedInfo.getInstance(null);
			Signature.getInstance(null);
			Signature.getInstance(null);
			SingleResponse.getInstance(null);
			SingleResponse.getInstance(null);
			TBSRequest.getInstance(null);
			TBSRequest.getInstance(null);
			Attribute.getInstance(null);
			AuthenticatedSafe.getInstance(null);
			CertificationRequestInfo.getInstance(null);
			CertificationRequest.getInstance(null);
			ContentInfo.getInstance(null);
			DHParameter.getInstance(null);
			EncryptedData.getInstance(null);
			EncryptedPrivateKeyInfo.getInstance(null);
			AlgorithmIdentifier.getInstance(null);
			IssuerAndSerialNumber.getInstance(null);
			MacData.getInstance(null);
			PBEParameter.getInstance(null);
			PBES2Parameters.getInstance(null);
			PBKDF2Params.getInstance(null);
			Pfx.getInstance(null);
			PKCS12PBEParams.getInstance(null);
			PrivateKeyInfo.getInstance(null);
			PrivateKeyInfo.getInstance(null);
			RC2CBCParameter.getInstance(null);
			RSAESOAEPparams.getInstance(null);
			RSAPrivateKey.getInstance(null);
			RSAPrivateKey.getInstance(null);
			RSAPublicKey.getInstance(null);
			RSAPublicKey.getInstance(null);
			RSASSAPSSparams.getInstance(null);
			SafeBag.getInstance(null);
			SignedData.getInstance(null);
			SignerInfo.getInstance(null);
			ECPrivateKey.getInstance(null);
			SMIMECapabilities.getInstance(null);
			SMIMECapability.getInstance(null);
			Accuracy.getInstance(null);
			MessageImprint.getInstance(null);
			TimeStampReq.getInstance(null);
			TimeStampResp.getInstance(null);
			TSTInfo.getInstance(null);
			AttributeTypeAndValue.getInstance(null);
			DirectoryString.getInstance(null);
			DirectoryString.getInstance(null);
			RDN.getInstance(null);
			X500Name.getInstance(null);
			X500Name.getInstance(null);
			AccessDescription.getInstance(null);
			AlgorithmIdentifier.getInstance(null);
			AlgorithmIdentifier.getInstance(null);
			AttCertIssuer.getInstance(null);
			AttCertIssuer.getInstance(null);
			AttCertValidityPeriod.getInstance(null);
			AttributeCertificateInfo.getInstance(null);
			AttributeCertificateInfo.getInstance(null);
			AttributeCertificate.getInstance(null);
			Attribute.getInstance(null);
			AuthorityInformationAccess.getInstance(null);
			AuthorityKeyIdentifier.getInstance(null);
			AuthorityKeyIdentifier.getInstance(null);
			BasicConstraints.getInstance(null);
			BasicConstraints.getInstance(null);
			Certificate.getInstance(null);
			Certificate.getInstance(null);
			CertificateList.getInstance(null);
			CertificateList.getInstance(null);
			CertificatePair.getInstance(null);
			CertificatePolicies.getInstance(null);
			CertificatePolicies.getInstance(null);
			CRLDistPoint.getInstance(null);
			CRLDistPoint.getInstance(null);
			CRLNumber.getInstance(null);
			CRLReason.getInstance(null);
			DigestInfo.getInstance(null);
			DigestInfo.getInstance(null);
			DisplayText.getInstance(null);
			DisplayText.getInstance(null);
			DistributionPoint.getInstance(null);
			DistributionPoint.getInstance(null);
			DistributionPointName.getInstance(null);
			DistributionPointName.getInstance(null);
			DSAParameter.getInstance(null);
			DSAParameter.getInstance(null);
			ExtendedKeyUsage.getInstance(null);
			ExtendedKeyUsage.getInstance(null);
			Extensions.getInstance(null);
			Extensions.getInstance(null);
			GeneralName.getInstance(null);
			GeneralName.getInstance(null);
			GeneralNames.getInstance(null);
			GeneralNames.getInstance(null);

			GeneralSubtree generalSubtree = new GeneralSubtree(new GeneralName(new X500Name("CN=Test")));
			ASN1ObjectIdentifier algOid = new ASN1ObjectIdentifier("1.2.1");
			ObjectDigestInfo objectDigestInfo = new ObjectDigestInfo(ObjectDigestInfo.otherObjectDigest, algOid, new AlgorithmIdentifier(algOid), new byte[20]);

			doFullGetInstanceTest(typeof(GeneralSubtree), generalSubtree);
			doFullGetInstanceTest(typeof(Holder), new Holder(objectDigestInfo));
			IetfAttrSyntax.getInstance(null);
			IssuerSerial.getInstance(null);
			IssuerSerial.getInstance(null);
			IssuingDistributionPoint.getInstance(null);
			IssuingDistributionPoint.getInstance(null);
			DERBitString.getInstance(null);

			v.clear();
			v.add(generalSubtree);

			doFullGetInstanceTest(typeof(NameConstraints), new NameConstraints(null, null));
			doFullGetInstanceTest(typeof(NoticeReference), noticeReference);
			doFullGetInstanceTest(typeof(ObjectDigestInfo), objectDigestInfo);

			PolicyInformation.getInstance(null);
			PolicyMappings.getInstance(null);
			PolicyQualifierInfo.getInstance(null);
			PrivateKeyUsagePeriod.getInstance(null);
			doFullGetInstanceTest(typeof(RoleSyntax), new RoleSyntax(new GeneralNames(new GeneralName(new X500Name("CN=Test"))), new GeneralName(GeneralName.uniformResourceIdentifier, "http://bc")));
			RSAPublicKey.getInstance(null);
			RSAPublicKey.getInstance(null);
			SubjectDirectoryAttributes.getInstance(null);
			SubjectKeyIdentifier.getInstance(null);
			SubjectKeyIdentifier.getInstance(null);
			SubjectPublicKeyInfo.getInstance(null);
			SubjectPublicKeyInfo.getInstance(null);
			TargetInformation.getInstance(null);
			Target.getInstance(null);
			Targets.getInstance(null);
			TBSCertificate.getInstance(null);
			TBSCertificate.getInstance(null);
			TBSCertificateStructure.getInstance(null);
			TBSCertificateStructure.getInstance(null);
			TBSCertList.CRLEntry.getInstance(null);
			TBSCertList.getInstance(null);
			TBSCertList.getInstance(null);
			Time.getInstance(null);
			Time.getInstance(null);
			doFullGetInstanceTest(typeof(UserNotice), new UserNotice(noticeReference, "hello world"));
			V2Form.getInstance(null);
			V2Form.getInstance(null);
			X509CertificateStructure.getInstance(null);
			X509CertificateStructure.getInstance(null);
			X509Extensions.getInstance(null);
			X509Extensions.getInstance(null);
			X500Name.getInstance(null);
			X500Name.getInstance(null);
			DHDomainParameters.getInstance(null);
			DHDomainParameters.getInstance(null);
			DHPublicKey.getInstance(null);
			DHPublicKey.getInstance(null);
			DHValidationParms.getInstance(null);
			DHValidationParms.getInstance(null);
			X962Parameters.getInstance(null);
			X962Parameters.getInstance(null);
			X9ECParameters.getInstance(null);
			MQVuserKeyingMaterial.getInstance(null);
			MQVuserKeyingMaterial.getInstance(null);
			CertHash.getInstance(null);
			RequestedCertificate.getInstance(null);
			RequestedCertificate.getInstance(null);
			AdditionalInformationSyntax.getInstance(null);
			Admissions.getInstance(null);
			AdmissionSyntax.getInstance(null);
			DeclarationOfMajority.getInstance(null);
			MonetaryLimit.getInstance(null);
			NamingAuthority.getInstance(null);
			NamingAuthority.getInstance(null);
			ProcurationSyntax.getInstance(null);
			ProfessionInfo.getInstance(null);
			Restriction.getInstance(null);
			BiometricData.getInstance(null);
			Iso4217CurrencyCode.getInstance(null);
			MonetaryValue.getInstance(null);
			QCStatement.getInstance(null);
			SemanticsInformation.getInstance(null);
			TypeOfBiometricData.getInstance(null);
			NameOrPseudonym.getInstance(null);
			PersonalData.getInstance(null);
		}

		public virtual string getName()
		{
			return "GetInstanceNullTest";
		}
	}

}