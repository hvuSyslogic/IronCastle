using org.bouncycastle.asn1.crmf;

namespace org.bouncycastle.cert.crmf
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using AttributeTypeAndValue = org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
	using CRMFObjectIdentifiers = org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
	using CertReqMsg = org.bouncycastle.asn1.crmf.CertReqMsg;
	using CertTemplate = org.bouncycastle.asn1.crmf.CertTemplate;
	using Controls = org.bouncycastle.asn1.crmf.Controls;
	using PKIArchiveOptions = org.bouncycastle.asn1.crmf.PKIArchiveOptions;
	using PKMACValue = org.bouncycastle.asn1.crmf.PKMACValue;
	using POPOSigningKey = org.bouncycastle.asn1.crmf.POPOSigningKey;
	using ProofOfPossession = org.bouncycastle.asn1.crmf.ProofOfPossession;
	using ContentVerifier = org.bouncycastle.@operator.ContentVerifier;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Encodable = org.bouncycastle.util.Encodable;

	/// <summary>
	/// Carrier for a CRMF CertReqMsg.
	/// </summary>
	public class CertificateRequestMessage : Encodable
	{
		public const int popRaVerified = ProofOfPossession.TYPE_RA_VERIFIED;
		public const int popSigningKey = ProofOfPossession.TYPE_SIGNING_KEY;
		public const int popKeyEncipherment = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
		public const int popKeyAgreement = ProofOfPossession.TYPE_KEY_AGREEMENT;

		private readonly CertReqMsg certReqMsg;
		private readonly Controls controls;

		private static CertReqMsg parseBytes(byte[] encoding)
		{
			try
			{
				return CertReqMsg.getInstance(ASN1Primitive.fromByteArray(encoding));
			}
			catch (ClassCastException e)
			{
				throw new CertIOException("malformed data: " + e.getMessage(), e);
			}
			catch (IllegalArgumentException e)
			{
				throw new CertIOException("malformed data: " + e.getMessage(), e);
			}
		}

		/// <summary>
		/// Create a CertificateRequestMessage from the passed in bytes.
		/// </summary>
		/// <param name="certReqMsg"> BER/DER encoding of the CertReqMsg structure. </param>
		/// <exception cref="IOException"> in the event of corrupted data, or an incorrect structure. </exception>
		public CertificateRequestMessage(byte[] certReqMsg) : this(parseBytes(certReqMsg))
		{
		}

		public CertificateRequestMessage(CertReqMsg certReqMsg)
		{
			this.certReqMsg = certReqMsg;
			this.controls = certReqMsg.getCertReq().getControls();
		}

		/// <summary>
		/// Return the underlying ASN.1 object defining this CertificateRequestMessage object.
		/// </summary>
		/// <returns> a CertReqMsg. </returns>
		public virtual CertReqMsg toASN1Structure()
		{
			return certReqMsg;
		}

		/// <summary>
		/// Return the certificate template contained in this message.
		/// </summary>
		/// <returns>  a CertTemplate structure. </returns>
		public virtual CertTemplate getCertTemplate()
		{
			return this.certReqMsg.getCertReq().getCertTemplate();
		}

		/// <summary>
		/// Return whether or not this request has control values associated with it.
		/// </summary>
		/// <returns> true if there are control values present, false otherwise. </returns>
		public virtual bool hasControls()
		{
			return controls != null;
		}

		/// <summary>
		/// Return whether or not this request has a specific type of control value.
		/// </summary>
		/// <param name="type"> the type OID for the control value we are checking for. </param>
		/// <returns> true if a control value of type is present, false otherwise. </returns>
		public virtual bool hasControl(ASN1ObjectIdentifier type)
		{
			return findControl(type) != null;
		}

		/// <summary>
		/// Return a control value of the specified type.
		/// </summary>
		/// <param name="type"> the type OID for the control value we are checking for. </param>
		/// <returns> the control value if present, null otherwise. </returns>
		public virtual Control getControl(ASN1ObjectIdentifier type)
		{
			AttributeTypeAndValue found = findControl(type);

			if (found != null)
			{
				if (found.getType().Equals(CRMFObjectIdentifiers_Fields.id_regCtrl_pkiArchiveOptions))
				{
					return new PKIArchiveControl(PKIArchiveOptions.getInstance(found.getValue()));
				}
				if (found.getType().Equals(CRMFObjectIdentifiers_Fields.id_regCtrl_regToken))
				{
					return new RegTokenControl(DERUTF8String.getInstance(found.getValue()));
				}
				if (found.getType().Equals(CRMFObjectIdentifiers_Fields.id_regCtrl_authenticator))
				{
					return new AuthenticatorControl(DERUTF8String.getInstance(found.getValue()));
				}
			}

			return null;
		}

		private AttributeTypeAndValue findControl(ASN1ObjectIdentifier type)
		{
			if (controls == null)
			{
				return null;
			}

			AttributeTypeAndValue[] tAndVs = controls.toAttributeTypeAndValueArray();
			AttributeTypeAndValue found = null;

			for (int i = 0; i != tAndVs.Length; i++)
			{
				if (tAndVs[i].getType().Equals(type))
				{
					found = tAndVs[i];
					break;
				}
			}

			return found;
		}

		/// <summary>
		/// Return whether or not this request message has a proof-of-possession field in it.
		/// </summary>
		/// <returns> true if proof-of-possession is present, false otherwise. </returns>
		public virtual bool hasProofOfPossession()
		{
			return this.certReqMsg.getPopo() != null;
		}

		/// <summary>
		/// Return the type of the proof-of-possession this request message provides.
		/// </summary>
		/// <returns> one of: popRaVerified, popSigningKey, popKeyEncipherment, popKeyAgreement </returns>
		public virtual int getProofOfPossessionType()
		{
			return this.certReqMsg.getPopo().getType();
		}

		/// <summary>
		/// Return whether or not the proof-of-possession (POP) is of the type popSigningKey and
		/// it has a public key MAC associated with it.
		/// </summary>
		/// <returns> true if POP is popSigningKey and a PKMAC is present, false otherwise. </returns>
		public virtual bool hasSigningKeyProofOfPossessionWithPKMAC()
		{
			ProofOfPossession pop = certReqMsg.getPopo();

			if (pop.getType() == popSigningKey)
			{
				POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

				return popoSign.getPoposkInput().getPublicKeyMAC() != null;
			}

			return false;
		}

		/// <summary>
		/// Return whether or not a signing key proof-of-possession (POP) is valid.
		/// </summary>
		/// <param name="verifierProvider"> a provider that can produce content verifiers for the signature contained in this POP. </param>
		/// <returns> true if the POP is valid, false otherwise. </returns>
		/// <exception cref="CRMFException"> if there is a problem in verification or content verifier creation. </exception>
		/// <exception cref="IllegalStateException"> if POP not appropriate. </exception>
		public virtual bool isValidSigningKeyPOP(ContentVerifierProvider verifierProvider)
		{
			ProofOfPossession pop = certReqMsg.getPopo();

			if (pop.getType() == popSigningKey)
			{
				POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

				if (popoSign.getPoposkInput() != null && popoSign.getPoposkInput().getPublicKeyMAC() != null)
				{
					throw new IllegalStateException("verification requires password check");
				}

				return verifySignature(verifierProvider, popoSign);
			}
			else
			{
				throw new IllegalStateException("not Signing Key type of proof of possession");
			}
		}

		/// <summary>
		/// Return whether or not a signing key proof-of-possession (POP), with an associated PKMAC, is valid.
		/// </summary>
		/// <param name="verifierProvider"> a provider that can produce content verifiers for the signature contained in this POP. </param>
		/// <param name="macBuilder"> a suitable PKMACBuilder to create the MAC verifier. </param>
		/// <param name="password"> the password used to key the MAC calculation. </param>
		/// <returns> true if the POP is valid, false otherwise. </returns>
		/// <exception cref="CRMFException"> if there is a problem in verification or content verifier creation. </exception>
		/// <exception cref="IllegalStateException"> if POP not appropriate. </exception>
		public virtual bool isValidSigningKeyPOP(ContentVerifierProvider verifierProvider, PKMACBuilder macBuilder, char[] password)
		{
			ProofOfPossession pop = certReqMsg.getPopo();

			if (pop.getType() == popSigningKey)
			{
				POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

				if (popoSign.getPoposkInput() == null || popoSign.getPoposkInput().getSender() != null)
				{
					throw new IllegalStateException("no PKMAC present in proof of possession");
				}

				PKMACValue pkMAC = popoSign.getPoposkInput().getPublicKeyMAC();
				PKMACValueVerifier macVerifier = new PKMACValueVerifier(macBuilder);

				if (macVerifier.isValid(pkMAC, password, this.getCertTemplate().getPublicKey()))
				{
					return verifySignature(verifierProvider, popoSign);
				}

				return false;
			}
			else
			{
				throw new IllegalStateException("not Signing Key type of proof of possession");
			}
		}

		private bool verifySignature(ContentVerifierProvider verifierProvider, POPOSigningKey popoSign)
		{
			ContentVerifier verifier;

			try
			{
				verifier = verifierProvider.get(popoSign.getAlgorithmIdentifier());
			}
			catch (OperatorCreationException e)
			{
				throw new CRMFException("unable to create verifier: " + e.Message, e);
			}

			if (popoSign.getPoposkInput() != null)
			{
				CRMFUtil.derEncodeToStream(popoSign.getPoposkInput(), verifier.getOutputStream());
			}
			else
			{
				CRMFUtil.derEncodeToStream(certReqMsg.getCertReq(), verifier.getOutputStream());
			}

			return verifier.verify(popoSign.getSignature().getOctets());
		}

		/// <summary>
		/// Return the ASN.1 encoding of the certReqMsg we wrap.
		/// </summary>
		/// <returns> a byte array containing the binary encoding of the certReqMsg. </returns>
		/// <exception cref="IOException"> if there is an exception creating the encoding. </exception>
		public virtual byte[] getEncoded()
		{
			return certReqMsg.getEncoded();
		}
	}
}