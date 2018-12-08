using System;

namespace org.bouncycastle.cert.crmf
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1Null = org.bouncycastle.asn1.ASN1Null;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using AttributeTypeAndValue = org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
	using CertReqMsg = org.bouncycastle.asn1.crmf.CertReqMsg;
	using CertRequest = org.bouncycastle.asn1.crmf.CertRequest;
	using CertTemplate = org.bouncycastle.asn1.crmf.CertTemplate;
	using CertTemplateBuilder = org.bouncycastle.asn1.crmf.CertTemplateBuilder;
	using OptionalValidity = org.bouncycastle.asn1.crmf.OptionalValidity;
	using PKMACValue = org.bouncycastle.asn1.crmf.PKMACValue;
	using POPOPrivKey = org.bouncycastle.asn1.crmf.POPOPrivKey;
	using ProofOfPossession = org.bouncycastle.asn1.crmf.ProofOfPossession;
	using SubsequentMessage = org.bouncycastle.asn1.crmf.SubsequentMessage;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Time = org.bouncycastle.asn1.x509.Time;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;

	public class CertificateRequestMessageBuilder
	{
		private readonly BigInteger certReqId;

		private ExtensionsGenerator extGenerator;
		private CertTemplateBuilder templateBuilder;
		private List controls;
		private ContentSigner popSigner;
		private PKMACBuilder pkmacBuilder;
		private char[] password;
		private GeneralName sender;
		private int popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
		private POPOPrivKey popoPrivKey;
		private ASN1Null popRaVerified;
		private PKMACValue agreeMAC;

		public CertificateRequestMessageBuilder(BigInteger certReqId)
		{
			this.certReqId = certReqId;

			this.extGenerator = new ExtensionsGenerator();
			this.templateBuilder = new CertTemplateBuilder();
			this.controls = new ArrayList();
		}

		public virtual CertificateRequestMessageBuilder setPublicKey(SubjectPublicKeyInfo publicKey)
		{
			if (publicKey != null)
			{
				templateBuilder.setPublicKey(publicKey);
			}

			return this;
		}

		public virtual CertificateRequestMessageBuilder setIssuer(X500Name issuer)
		{
			if (issuer != null)
			{
				templateBuilder.setIssuer(issuer);
			}

			return this;
		}

		public virtual CertificateRequestMessageBuilder setSubject(X500Name subject)
		{
			if (subject != null)
			{
				templateBuilder.setSubject(subject);
			}

			return this;
		}

		public virtual CertificateRequestMessageBuilder setSerialNumber(BigInteger serialNumber)
		{
			if (serialNumber != null)
			{
				templateBuilder.setSerialNumber(new ASN1Integer(serialNumber));
			}

			return this;
		}

		/// <summary>
		/// Request a validity period for the certificate. Either, but not both, of the date parameters may be null.
		/// </summary>
		/// <param name="notBeforeDate"> not before date for certificate requested. </param>
		/// <param name="notAfterDate"> not after date for the certificate requested.
		/// </param>
		/// <returns> the current builder. </returns>
		public virtual CertificateRequestMessageBuilder setValidity(DateTime notBeforeDate, DateTime notAfterDate)
		{
			templateBuilder.setValidity(new OptionalValidity(createTime(notBeforeDate), createTime(notAfterDate)));

			return this;
		}

		private Time createTime(DateTime date)
		{
			if (date != null)
			{
				return new Time(date);
			}

			return null;
		}

		public virtual CertificateRequestMessageBuilder addExtension(ASN1ObjectIdentifier oid, bool critical, ASN1Encodable value)
		{
			CRMFUtil.addExtension(extGenerator, oid, critical, value);

			return this;
		}

		public virtual CertificateRequestMessageBuilder addExtension(ASN1ObjectIdentifier oid, bool critical, byte[] value)
		{
			extGenerator.addExtension(oid, critical, value);

			return this;
		}

		public virtual CertificateRequestMessageBuilder addControl(Control control)
		{
			controls.add(control);

			return this;
		}

		public virtual CertificateRequestMessageBuilder setProofOfPossessionSigningKeySigner(ContentSigner popSigner)
		{
			if (popoPrivKey != null || popRaVerified != null || agreeMAC != null)
			{
				throw new IllegalStateException("only one proof of possession allowed");
			}

			this.popSigner = popSigner;

			return this;
		}

		public virtual CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(SubsequentMessage msg)
		{
			if (popSigner != null || popRaVerified != null || agreeMAC != null)
			{
				throw new IllegalStateException("only one proof of possession allowed");
			}

			this.popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
			this.popoPrivKey = new POPOPrivKey(msg);

			return this;
		}

		public virtual CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(int type, SubsequentMessage msg)
		{
			if (popSigner != null || popRaVerified != null || agreeMAC != null)
			{
				throw new IllegalStateException("only one proof of possession allowed");
			}
			if (type != ProofOfPossession.TYPE_KEY_ENCIPHERMENT && type != ProofOfPossession.TYPE_KEY_AGREEMENT)
			{
				throw new IllegalArgumentException("type must be ProofOfPossession.TYPE_KEY_ENCIPHERMENT || ProofOfPossession.TYPE_KEY_AGREEMENT");
			}

			this.popoType = type;
			this.popoPrivKey = new POPOPrivKey(msg);

			return this;
		}

		public virtual CertificateRequestMessageBuilder setProofOfPossessionAgreeMAC(PKMACValue macValue)
		{
			if (popSigner != null || popRaVerified != null || popoPrivKey != null)
			{
				throw new IllegalStateException("only one proof of possession allowed");
			}

			this.agreeMAC = macValue;

			return this;
		}

		public virtual CertificateRequestMessageBuilder setProofOfPossessionRaVerified()
		{
			if (popSigner != null || popoPrivKey != null)
			{
				throw new IllegalStateException("only one proof of possession allowed");
			}

			this.popRaVerified = DERNull.INSTANCE;

			return this;
		}

		public virtual CertificateRequestMessageBuilder setAuthInfoPKMAC(PKMACBuilder pkmacBuilder, char[] password)
		{
			this.pkmacBuilder = pkmacBuilder;
			this.password = password;

			return this;
		}

		public virtual CertificateRequestMessageBuilder setAuthInfoSender(X500Name sender)
		{
			return setAuthInfoSender(new GeneralName(sender));
		}

		public virtual CertificateRequestMessageBuilder setAuthInfoSender(GeneralName sender)
		{
			this.sender = sender;

			return this;
		}

		public virtual CertificateRequestMessage build()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(certReqId));

			if (!extGenerator.isEmpty())
			{
				templateBuilder.setExtensions(extGenerator.generate());
			}

			v.add(templateBuilder.build());

			if (!controls.isEmpty())
			{
				ASN1EncodableVector controlV = new ASN1EncodableVector();

				for (Iterator it = controls.iterator(); it.hasNext();)
				{
					Control control = (Control)it.next();

					controlV.add(new AttributeTypeAndValue(control.getType(), control.getValue()));
				}

				v.add(new DERSequence(controlV));
			}

			CertRequest request = CertRequest.getInstance(new DERSequence(v));

			v = new ASN1EncodableVector();

			v.add(request);

			if (popSigner != null)
			{
				CertTemplate template = request.getCertTemplate();

				if (template.getSubject() == null || template.getPublicKey() == null)
				{
					SubjectPublicKeyInfo pubKeyInfo = request.getCertTemplate().getPublicKey();
					ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

					if (sender != null)
					{
						builder.setSender(sender);
					}
					else
					{
						PKMACValueGenerator pkmacGenerator = new PKMACValueGenerator(pkmacBuilder);

						builder.setPublicKeyMac(pkmacGenerator, password);
					}

					v.add(new ProofOfPossession(builder.build(popSigner)));
				}
				else
				{
					ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(request);

					v.add(new ProofOfPossession(builder.build(popSigner)));
				}
			}
			else if (popoPrivKey != null)
			{
				v.add(new ProofOfPossession(popoType, popoPrivKey));
			}
			else if (agreeMAC != null)
			{
				v.add(new ProofOfPossession(ProofOfPossession.TYPE_KEY_AGREEMENT, POPOPrivKey.getInstance(new DERTaggedObject(false, POPOPrivKey.agreeMAC, agreeMAC))));

			}
			else if (popRaVerified != null)
			{
				v.add(new ProofOfPossession());
			}

			return new CertificateRequestMessage(CertReqMsg.getInstance(new DERSequence(v)));
		}
	}
}