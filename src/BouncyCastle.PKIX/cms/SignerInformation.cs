using org.bouncycastle.asn1.cms;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cms
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;
	using CMSAlgorithmProtection = org.bouncycastle.asn1.cms.CMSAlgorithmProtection;
	using CMSAttributes = org.bouncycastle.asn1.cms.CMSAttributes;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using SignerIdentifier = org.bouncycastle.asn1.cms.SignerIdentifier;
	using SignerInfo = org.bouncycastle.asn1.cms.SignerInfo;
	using Time = org.bouncycastle.asn1.cms.Time;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using RawContentVerifier = org.bouncycastle.@operator.RawContentVerifier;
	using Arrays = org.bouncycastle.util.Arrays;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	/// <summary>
	/// an expanded SignerInfo block from a CMS Signed message
	/// </summary>
	public class SignerInformation
	{
		private readonly SignerId sid;
		private readonly CMSProcessable content;
		private readonly byte[] signature;
		private readonly ASN1ObjectIdentifier contentType;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private readonly bool isCounterSignature_Renamed;

		// Derived
		private AttributeTable signedAttributeValues;
		private AttributeTable unsignedAttributeValues;
		private byte[] resultDigest;

		protected internal readonly SignerInfo info;
		protected internal readonly AlgorithmIdentifier digestAlgorithm;
		protected internal readonly AlgorithmIdentifier encryptionAlgorithm;
		protected internal readonly ASN1Set signedAttributeSet;
		protected internal readonly ASN1Set unsignedAttributeSet;

		public SignerInformation(SignerInfo info, ASN1ObjectIdentifier contentType, CMSProcessable content, byte[] resultDigest)
		{
			this.info = info;
			this.contentType = contentType;
			this.isCounterSignature_Renamed = contentType == null;

			SignerIdentifier s = info.getSID();

			if (s.isTagged())
			{
				ASN1OctetString octs = ASN1OctetString.getInstance(s.getId());

				sid = new SignerId(octs.getOctets());
			}
			else
			{
				IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(s.getId());

				sid = new SignerId(iAnds.getName(), iAnds.getSerialNumber().getValue());
			}

			this.digestAlgorithm = info.getDigestAlgorithm();
			this.signedAttributeSet = info.getAuthenticatedAttributes();
			this.unsignedAttributeSet = info.getUnauthenticatedAttributes();
			this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
			this.signature = info.getEncryptedDigest().getOctets();

			this.content = content;
			this.resultDigest = resultDigest;
		}

		/// <summary>
		/// Protected constructor. In some cases clients have their own idea about how to encode
		/// the signed attributes and calculate the signature. This constructor is to allow developers
		/// to deal with that by extending off the class and overridng methods like getSignedAttributes().
		/// </summary>
		/// <param name="baseInfo"> the SignerInformation to base this one on. </param>
		public SignerInformation(SignerInformation baseInfo)
		{
			this.info = baseInfo.info;
			this.contentType = baseInfo.contentType;
			this.isCounterSignature_Renamed = baseInfo.isCounterSignature();
			this.sid = baseInfo.getSID();
			this.digestAlgorithm = info.getDigestAlgorithm();
			this.signedAttributeSet = info.getAuthenticatedAttributes();
			this.unsignedAttributeSet = info.getUnauthenticatedAttributes();
			this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
			this.signature = info.getEncryptedDigest().getOctets();
			this.content = baseInfo.content;
			this.resultDigest = baseInfo.resultDigest;
			this.signedAttributeValues = baseInfo.signedAttributeValues;
			this.unsignedAttributeValues = baseInfo.unsignedAttributeValues;
		}

		public virtual bool isCounterSignature()
		{
			return isCounterSignature_Renamed;
		}

		public virtual ASN1ObjectIdentifier getContentType()
		{
			return this.contentType;
		}

		private byte[] encodeObj(ASN1Encodable obj)
		{
			if (obj != null)
			{
				return obj.toASN1Primitive().getEncoded();
			}

			return null;
		}

		public virtual SignerId getSID()
		{
			return sid;
		}

		/// <summary>
		/// return the version number for this objects underlying SignerInfo structure.
		/// </summary>
		public virtual int getVersion()
		{
			return info.getVersion().getValue().intValue();
		}

		public virtual AlgorithmIdentifier getDigestAlgorithmID()
		{
			return digestAlgorithm;
		}

		/// <summary>
		/// return the object identifier for the signature.
		/// </summary>
		public virtual string getDigestAlgOID()
		{
			return digestAlgorithm.getAlgorithm().getId();
		}

		/// <summary>
		/// return the signature parameters, or null if there aren't any.
		/// </summary>
		public virtual byte[] getDigestAlgParams()
		{
			try
			{
				return encodeObj(digestAlgorithm.getParameters());
			}
			catch (Exception e)
			{
				throw new RuntimeException("exception getting digest parameters " + e);
			}
		}

		/// <summary>
		/// return the content digest that was calculated during verification.
		/// </summary>
		public virtual byte[] getContentDigest()
		{
			if (resultDigest == null)
			{
				throw new IllegalStateException("method can only be called after verify.");
			}

			return Arrays.clone(resultDigest);
		}

		/// <summary>
		/// return the object identifier for the signature.
		/// </summary>
		public virtual string getEncryptionAlgOID()
		{
			return encryptionAlgorithm.getAlgorithm().getId();
		}

		/// <summary>
		/// return the signature/encryption algorithm parameters, or null if
		/// there aren't any.
		/// </summary>
		public virtual byte[] getEncryptionAlgParams()
		{
			try
			{
				return encodeObj(encryptionAlgorithm.getParameters());
			}
			catch (Exception e)
			{
				throw new RuntimeException("exception getting encryption parameters " + e);
			}
		}

		/// <summary>
		/// return a table of the signed attributes - indexed by
		/// the OID of the attribute.
		/// </summary>
		public virtual AttributeTable getSignedAttributes()
		{
			if (signedAttributeSet != null && signedAttributeValues == null)
			{
				signedAttributeValues = new AttributeTable(signedAttributeSet);
			}

			return signedAttributeValues;
		}

		/// <summary>
		/// return a table of the unsigned attributes indexed by
		/// the OID of the attribute.
		/// </summary>
		public virtual AttributeTable getUnsignedAttributes()
		{
			if (unsignedAttributeSet != null && unsignedAttributeValues == null)
			{
				unsignedAttributeValues = new AttributeTable(unsignedAttributeSet);
			}

			return unsignedAttributeValues;
		}

		/// <summary>
		/// return the encoded signature
		/// </summary>
		public virtual byte[] getSignature()
		{
			return Arrays.clone(signature);
		}

		/// <summary>
		/// Return a SignerInformationStore containing the counter signatures attached to this
		/// signer. If no counter signatures are present an empty store is returned.
		/// </summary>
		public virtual SignerInformationStore getCounterSignatures()
		{
			// TODO There are several checks implied by the RFC3852 comments that are missing

			/*
			The countersignature attribute MUST be an unsigned attribute; it MUST
			NOT be a signed attribute, an authenticated attribute, an
			unauthenticated attribute, or an unprotected attribute.
			*/        
			AttributeTable unsignedAttributeTable = getUnsignedAttributes();
			if (unsignedAttributeTable == null)
			{
				return new SignerInformationStore(new ArrayList(0));
			}

			List counterSignatures = new ArrayList();

			/*
			The UnsignedAttributes syntax is defined as a SET OF Attributes.  The
			UnsignedAttributes in a signerInfo may include multiple instances of
			the countersignature attribute.
			*/
			ASN1EncodableVector allCSAttrs = unsignedAttributeTable.getAll(CMSAttributes_Fields.counterSignature);

			for (int i = 0; i < allCSAttrs.size(); ++i)
			{
				Attribute counterSignatureAttribute = (Attribute)allCSAttrs.get(i);

				/*
				A countersignature attribute can have multiple attribute values.  The
				syntax is defined as a SET OF AttributeValue, and there MUST be one
				or more instances of AttributeValue present.
				*/
				ASN1Set values = counterSignatureAttribute.getAttrValues();
				if (values.size() < 1)
				{
					// TODO Throw an appropriate exception?
				}

				for (Enumeration en = values.getObjects(); en.hasMoreElements();)
				{
					/*
					Countersignature values have the same meaning as SignerInfo values
					for ordinary signatures, except that:
	
					   1. The signedAttributes field MUST NOT contain a content-type
					      attribute; there is no content type for countersignatures.
	
					   2. The signedAttributes field MUST contain a message-digest
					      attribute if it contains any other attributes.
	
					   3. The input to the message-digesting process is the contents
					      octets of the DER encoding of the signatureValue field of the
					      SignerInfo value with which the attribute is associated.
					*/
					SignerInfo si = SignerInfo.getInstance(en.nextElement());

					counterSignatures.add(new SignerInformation(si, null, new CMSProcessableByteArray(getSignature()), null));
				}
			}

			return new SignerInformationStore(counterSignatures);
		}

		/// <summary>
		/// return the DER encoding of the signed attributes. </summary>
		/// <exception cref="IOException"> if an encoding error occurs. </exception>
		public virtual byte[] getEncodedSignedAttributes()
		{
			if (signedAttributeSet != null)
			{
				return signedAttributeSet.getEncoded(ASN1Encoding_Fields.DER);
			}

			return null;
		}

		private bool doVerify(SignerInformationVerifier verifier)
		{
			string encName = CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.getEncryptionAlgOID());
			ContentVerifier contentVerifier;

			try
			{
				contentVerifier = verifier.getContentVerifier(encryptionAlgorithm, info.getDigestAlgorithm());
			}
			catch (OperatorCreationException e)
			{
				throw new CMSException("can't create content verifier: " + e.Message, e);
			}

			try
			{
				OutputStream sigOut = contentVerifier.getOutputStream();

				if (resultDigest == null)
				{
					DigestCalculator calc = verifier.getDigestCalculator(this.getDigestAlgorithmID());
					if (content != null)
					{
						OutputStream digOut = calc.getOutputStream();

						if (signedAttributeSet == null)
						{
							if (contentVerifier is RawContentVerifier)
							{
								content.write(digOut);
							}
							else
							{
								OutputStream cOut = new TeeOutputStream(digOut, sigOut);

								content.write(cOut);

								cOut.close();
							}
						}
						else
						{
							content.write(digOut);
							sigOut.write(this.getEncodedSignedAttributes());
						}

						digOut.close();
					}
					else if (signedAttributeSet != null)
					{
						sigOut.write(this.getEncodedSignedAttributes());
					}
					else
					{
						// TODO Get rid of this exception and just treat content==null as empty not missing?
						throw new CMSException("data not encapsulated in signature - use detached constructor.");
					}

					resultDigest = calc.getDigest();
				}
				else
				{
					if (signedAttributeSet == null)
					{
						if (content != null)
						{
							content.write(sigOut);
						}
					}
					else
					{
						sigOut.write(this.getEncodedSignedAttributes());
					}
				}

				sigOut.close();
			}
			catch (IOException e)
			{
				throw new CMSException("can't process mime object to create signature.", e);
			}
			catch (OperatorCreationException e)
			{
				throw new CMSException("can't create digest calculator: " + e.Message, e);
			}

			{
			// RFC 3852 11.1 Check the content-type attribute is correct
				ASN1Primitive validContentType = getSingleValuedSignedAttribute(CMSAttributes_Fields.contentType, "content-type");
				if (validContentType == null)
				{
					if (!isCounterSignature_Renamed && signedAttributeSet != null)
					{
						throw new CMSException("The content-type attribute type MUST be present whenever signed attributes are present in signed-data");
					}
				}
				else
				{
					if (isCounterSignature_Renamed)
					{
						throw new CMSException("[For counter signatures,] the signedAttributes field MUST NOT contain a content-type attribute");
					}

					if (!(validContentType is ASN1ObjectIdentifier))
					{
						throw new CMSException("content-type attribute value not of ASN.1 type 'OBJECT IDENTIFIER'");
					}

					ASN1ObjectIdentifier signedContentType = (ASN1ObjectIdentifier)validContentType;

					if (!signedContentType.Equals(contentType))
					{
						throw new CMSException("content-type attribute value does not match eContentType");
					}
				}
			}

			AttributeTable signedAttrTable = this.getSignedAttributes();

			{
			// RFC 6211 Validate Algorithm Identifier protection attribute if present
				AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
				if (unsignedAttrTable != null && unsignedAttrTable.getAll(CMSAttributes_Fields.cmsAlgorithmProtect).size() > 0)
				{
					throw new CMSException("A cmsAlgorithmProtect attribute MUST be a signed attribute");
				}
				if (signedAttrTable != null)
				{
					ASN1EncodableVector protectionAttributes = signedAttrTable.getAll(CMSAttributes_Fields.cmsAlgorithmProtect);
					if (protectionAttributes.size() > 1)
					{
						throw new CMSException("Only one instance of a cmsAlgorithmProtect attribute can be present");
					}

					if (protectionAttributes.size() > 0)
					{
						Attribute attr = Attribute.getInstance(protectionAttributes.get(0));
						if (attr.getAttrValues().size() != 1)
						{
							throw new CMSException("A cmsAlgorithmProtect attribute MUST contain exactly one value");
						}

						CMSAlgorithmProtection algorithmProtection = CMSAlgorithmProtection.getInstance(attr.getAttributeValues()[0]);

						if (!CMSUtils.isEquivalent(algorithmProtection.getDigestAlgorithm(), info.getDigestAlgorithm()))
						{
							throw new CMSException("CMS Algorithm Identifier Protection check failed for digestAlgorithm");
						}

						if (!CMSUtils.isEquivalent(algorithmProtection.getSignatureAlgorithm(), info.getDigestEncryptionAlgorithm()))
						{
							throw new CMSException("CMS Algorithm Identifier Protection check failed for signatureAlgorithm");
						}
					}
				}
			}

			{
			// RFC 3852 11.2 Check the message-digest attribute is correct
				ASN1Primitive validMessageDigest = getSingleValuedSignedAttribute(CMSAttributes_Fields.messageDigest, "message-digest");
				if (validMessageDigest == null)
				{
					if (signedAttributeSet != null)
					{
						throw new CMSException("the message-digest signed attribute type MUST be present when there are any signed attributes present");
					}
				}
				else
				{
					if (!(validMessageDigest is ASN1OctetString))
					{
						throw new CMSException("message-digest attribute value not of ASN.1 type 'OCTET STRING'");
					}

					ASN1OctetString signedMessageDigest = (ASN1OctetString)validMessageDigest;

					if (!Arrays.constantTimeAreEqual(resultDigest, signedMessageDigest.getOctets()))
					{
						throw new CMSSignerDigestMismatchException("message-digest attribute value does not match calculated value");
					}
				}
			}

			{
			// RFC 3852 11.4 Validate countersignature attribute(s)
				if (signedAttrTable != null && signedAttrTable.getAll(CMSAttributes_Fields.counterSignature).size() > 0)
				{
					throw new CMSException("A countersignature attribute MUST NOT be a signed attribute");
				}

				AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
				if (unsignedAttrTable != null)
				{
					ASN1EncodableVector csAttrs = unsignedAttrTable.getAll(CMSAttributes_Fields.counterSignature);
					for (int i = 0; i < csAttrs.size(); ++i)
					{
						Attribute csAttr = Attribute.getInstance(csAttrs.get(i));
						if (csAttr.getAttrValues().size() < 1)
						{
							throw new CMSException("A countersignature attribute MUST contain at least one AttributeValue");
						}

						// Note: We don't recursively validate the countersignature value
					}
				}
			}

			try
			{
				if (signedAttributeSet == null && resultDigest != null)
				{
					if (contentVerifier is RawContentVerifier)
					{
						RawContentVerifier rawVerifier = (RawContentVerifier)contentVerifier;

						if (encName.Equals("RSA"))
						{
							DigestInfo digInfo = new DigestInfo(new AlgorithmIdentifier(digestAlgorithm.getAlgorithm(), DERNull.INSTANCE), resultDigest);

							return rawVerifier.verify(digInfo.getEncoded(ASN1Encoding_Fields.DER), this.getSignature());
						}

						return rawVerifier.verify(resultDigest, this.getSignature());
					}
				}

				return contentVerifier.verify(this.getSignature());
			}
			catch (IOException e)
			{
				throw new CMSException("can't process mime object to create signature.", e);
			}
		}

		/// <summary>
		/// Verify that the given verifier can successfully verify the signature on
		/// this SignerInformation object.
		/// </summary>
		/// <param name="verifier"> a suitably configured SignerInformationVerifier. </param>
		/// <returns> true if the signer information is verified, false otherwise. </returns>
		/// <exception cref="org.bouncycastle.cms.CMSVerifierCertificateNotValidException"> if the provider has an associated certificate and the certificate is not valid at the time given as the SignerInfo's signing time. </exception>
		/// <exception cref="org.bouncycastle.cms.CMSException"> if the verifier is unable to create a ContentVerifiers or DigestCalculators. </exception>
		public virtual bool verify(SignerInformationVerifier verifier)
		{
			Time signingTime = getSigningTime(); // has to be validated if present.

			if (verifier.hasAssociatedCertificate())
			{
				if (signingTime != null)
				{
					X509CertificateHolder dcv = verifier.getAssociatedCertificate();

					if (!dcv.isValidOn(signingTime.getDate()))
					{
						throw new CMSVerifierCertificateNotValidException("verifier not valid at signingTime");
					}
				}
			}

			return doVerify(verifier);
		}

		/// <summary>
		/// Return the underlying ASN.1 object defining this SignerInformation object.
		/// </summary>
		/// <returns> a SignerInfo. </returns>
		public virtual SignerInfo toASN1Structure()
		{
			return info;
		}

		private ASN1Primitive getSingleValuedSignedAttribute(ASN1ObjectIdentifier attrOID, string printableName)
		{
			AttributeTable unsignedAttrTable = this.getUnsignedAttributes();
			if (unsignedAttrTable != null && unsignedAttrTable.getAll(attrOID).size() > 0)
			{
				throw new CMSException("The " + printableName + " attribute MUST NOT be an unsigned attribute");
			}

			AttributeTable signedAttrTable = this.getSignedAttributes();
			if (signedAttrTable == null)
			{
				return null;
			}

			ASN1EncodableVector v = signedAttrTable.getAll(attrOID);
			switch (v.size())
			{
				case 0:
					return null;
				case 1:
				{
					Attribute t = (Attribute)v.get(0);
					ASN1Set attrValues = t.getAttrValues();
					if (attrValues.size() != 1)
					{
						throw new CMSException("A " + printableName + " attribute MUST have a single attribute value");
					}

					return attrValues.getObjectAt(0).toASN1Primitive();
				}
				default:
					throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the " + printableName + " attribute");
			}
		}

		private Time getSigningTime()
		{
			ASN1Primitive validSigningTime = getSingleValuedSignedAttribute(CMSAttributes_Fields.signingTime, "signing-time");

			if (validSigningTime == null)
			{
				return null;
			}

			try
			{
				return Time.getInstance(validSigningTime);
			}
			catch (IllegalArgumentException)
			{
				throw new CMSException("signing-time attribute value not a valid 'Time' structure");
			}
		}

		/// <summary>
		/// Return a signer information object with the passed in unsigned
		/// attributes replacing the ones that are current associated with
		/// the object passed in.
		/// </summary>
		/// <param name="signerInformation"> the signerInfo to be used as the basis. </param>
		/// <param name="unsignedAttributes"> the unsigned attributes to add. </param>
		/// <returns> a copy of the original SignerInformationObject with the changed attributes. </returns>
		public static SignerInformation replaceUnsignedAttributes(SignerInformation signerInformation, AttributeTable unsignedAttributes)
		{
			SignerInfo sInfo = signerInformation.info;
			ASN1Set unsignedAttr = null;

			if (unsignedAttributes != null)
			{
				unsignedAttr = new DERSet(unsignedAttributes.toASN1EncodableVector());
			}

			return new SignerInformation(new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(), sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), unsignedAttr), signerInformation.contentType, signerInformation.content, null);
		}

		/// <summary>
		/// Return a signer information object with passed in SignerInformationStore representing counter
		/// signatures attached as an unsigned attribute.
		/// </summary>
		/// <param name="signerInformation"> the signerInfo to be used as the basis. </param>
		/// <param name="counterSigners"> signer info objects carrying counter signature. </param>
		/// <returns> a copy of the original SignerInformationObject with the changed attributes. </returns>
		public static SignerInformation addCounterSigners(SignerInformation signerInformation, SignerInformationStore counterSigners)
		{
			// TODO Perform checks from RFC 3852 11.4

			SignerInfo sInfo = signerInformation.info;
			AttributeTable unsignedAttr = signerInformation.getUnsignedAttributes();
			ASN1EncodableVector v;

			if (unsignedAttr != null)
			{
				v = unsignedAttr.toASN1EncodableVector();
			}
			else
			{
				v = new ASN1EncodableVector();
			}

			ASN1EncodableVector sigs = new ASN1EncodableVector();

			for (Iterator it = counterSigners.getSigners().iterator(); it.hasNext();)
			{
				sigs.add(((SignerInformation)it.next()).toASN1Structure());
			}

			v.add(new Attribute(CMSAttributes_Fields.counterSignature, new DERSet(sigs)));

			return new SignerInformation(new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(), sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), new DERSet(v)), signerInformation.contentType, signerInformation.content, null);
		}
	}

}