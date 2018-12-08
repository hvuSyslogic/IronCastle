using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

namespace org.bouncycastle.jce.provider
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DHDomainParameters = org.bouncycastle.asn1.x9.DHDomainParameters;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;

	public class JCEDHPrivateKey : DHPrivateKey, PKCS12BagAttributeCarrier
	{
		internal const long serialVersionUID = 311058815616901812L;

		internal BigInteger x;

		private DHParameterSpec dhSpec;
		private PrivateKeyInfo info;

		private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public JCEDHPrivateKey()
		{
		}

		public JCEDHPrivateKey(DHPrivateKey key)
		{
			this.x = key.getX();
			this.dhSpec = key.getParams();
		}

		public JCEDHPrivateKey(DHPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.dhSpec = new DHParameterSpec(spec.getP(), spec.getG());
		}

		public JCEDHPrivateKey(PrivateKeyInfo info)
		{
			ASN1Sequence seq = ASN1Sequence.getInstance(info.getPrivateKeyAlgorithm().getParameters());
			ASN1Integer derX = ASN1Integer.getInstance(info.parsePrivateKey());
			ASN1ObjectIdentifier id = info.getPrivateKeyAlgorithm().getAlgorithm();

			this.info = info;
			this.x = derX.getValue();

			if (id.Equals(PKCSObjectIdentifiers_Fields.dhKeyAgreement))
			{
				DHParameter @params = DHParameter.getInstance(seq);

				if (@params.getL() != null)
				{
					this.dhSpec = new DHParameterSpec(@params.getP(), @params.getG(), @params.getL().intValue());
				}
				else
				{
					this.dhSpec = new DHParameterSpec(@params.getP(), @params.getG());
				}
			}
			else if (id.Equals(X9ObjectIdentifiers_Fields.dhpublicnumber))
			{
				DHDomainParameters @params = DHDomainParameters.getInstance(seq);

				this.dhSpec = new DHParameterSpec(@params.getP().getValue(), @params.getG().getValue());
			}
			else
			{
				throw new IllegalArgumentException("unknown algorithm type: " + id);
			}
		}

		public JCEDHPrivateKey(DHPrivateKeyParameters @params)
		{
			this.x = @params.getX();
			this.dhSpec = new DHParameterSpec(@params.getParameters().getP(), @params.getParameters().getG(), @params.getParameters().getL());
		}

		public virtual string getAlgorithm()
		{
			return "DH";
		}

		/// <summary>
		/// return the encoding format we produce in getEncoded().
		/// </summary>
		/// <returns> the string "PKCS#8" </returns>
		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		/// <summary>
		/// Return a PKCS8 representation of the key. The sequence returned
		/// represents a full PrivateKeyInfo object.
		/// </summary>
		/// <returns> a PKCS8 representation of the key. </returns>
		public virtual byte[] getEncoded()
		{
			try
			{
				if (info != null)
				{
					return info.getEncoded(ASN1Encoding_Fields.DER);
				}

				PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.dhKeyAgreement, new DHParameter(dhSpec.getP(), dhSpec.getG(), dhSpec.getL())), new ASN1Integer(getX()));

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual DHParameterSpec getParams()
		{
			return dhSpec;
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		private void readObject(ObjectInputStream @in)
		{
			x = (BigInteger)@in.readObject();

			this.dhSpec = new DHParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), @in.readInt());
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(this.getX());
			@out.writeObject(dhSpec.getP());
			@out.writeObject(dhSpec.getG());
			@out.writeInt(dhSpec.getL());
		}

		public virtual void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute)
		{
			attrCarrier.setBagAttribute(oid, attribute);
		}

		public virtual ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid)
		{
			return attrCarrier.getBagAttribute(oid);
		}

		public virtual Enumeration getBagAttributeKeys()
		{
			return attrCarrier.getBagAttributeKeys();
		}
	}

}