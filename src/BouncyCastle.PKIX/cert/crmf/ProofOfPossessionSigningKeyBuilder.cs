namespace org.bouncycastle.cert.crmf
{
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using CertRequest = org.bouncycastle.asn1.crmf.CertRequest;
	using PKMACValue = org.bouncycastle.asn1.crmf.PKMACValue;
	using POPOSigningKey = org.bouncycastle.asn1.crmf.POPOSigningKey;
	using POPOSigningKeyInput = org.bouncycastle.asn1.crmf.POPOSigningKeyInput;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;

	public class ProofOfPossessionSigningKeyBuilder
	{
		private CertRequest certRequest;
		private SubjectPublicKeyInfo pubKeyInfo;
		private GeneralName name;
		private PKMACValue publicKeyMAC;

		public ProofOfPossessionSigningKeyBuilder(CertRequest certRequest)
		{
			this.certRequest = certRequest;
		}


		public ProofOfPossessionSigningKeyBuilder(SubjectPublicKeyInfo pubKeyInfo)
		{
			this.pubKeyInfo = pubKeyInfo;
		}

		public virtual ProofOfPossessionSigningKeyBuilder setSender(GeneralName name)
		{
			this.name = name;

			return this;
		}

		public virtual ProofOfPossessionSigningKeyBuilder setPublicKeyMac(PKMACValueGenerator generator, char[] password)
		{
			this.publicKeyMAC = generator.generate(password, pubKeyInfo);

			return this;
		}

		public virtual POPOSigningKey build(ContentSigner signer)
		{
			if (name != null && publicKeyMAC != null)
			{
				throw new IllegalStateException("name and publicKeyMAC cannot both be set.");
			}

			POPOSigningKeyInput popo;

			if (certRequest != null)
			{
				popo = null;

				CRMFUtil.derEncodeToStream(certRequest, signer.getOutputStream());
			}
			else if (name != null)
			{
				popo = new POPOSigningKeyInput(name, pubKeyInfo);

				CRMFUtil.derEncodeToStream(popo, signer.getOutputStream());
			}
			else
			{
				popo = new POPOSigningKeyInput(publicKeyMAC, pubKeyInfo);

				CRMFUtil.derEncodeToStream(popo, signer.getOutputStream());
			}

			return new POPOSigningKey(popo, signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature()));
		}
	}

}