using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.jce.provider
{


	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using ElGamalPrivateKeyParameters = org.bouncycastle.crypto.@params.ElGamalPrivateKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using ElGamalPrivateKey = org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;
	using ElGamalPrivateKeySpec = org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;

	public class JCEElGamalPrivateKey : ElGamalPrivateKey, DHPrivateKey, PKCS12BagAttributeCarrier
	{
		internal const long serialVersionUID = 4819350091141529678L;

		internal BigInteger x;

		internal ElGamalParameterSpec elSpec;

		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public JCEElGamalPrivateKey()
		{
		}

		public JCEElGamalPrivateKey(ElGamalPrivateKey key)
		{
			this.x = key.getX();
			this.elSpec = key.getParameters();
		}

		public JCEElGamalPrivateKey(DHPrivateKey key)
		{
			this.x = key.getX();
			this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
		}

		public JCEElGamalPrivateKey(ElGamalPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
		}

		public JCEElGamalPrivateKey(DHPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
		}

		public JCEElGamalPrivateKey(PrivateKeyInfo info)
		{
			ElGamalParameter @params = ElGamalParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
			ASN1Integer derX = ASN1Integer.getInstance(info.parsePrivateKey());

			this.x = derX.getValue();
			this.elSpec = new ElGamalParameterSpec(@params.getP(), @params.getG());
		}

		public JCEElGamalPrivateKey(ElGamalPrivateKeyParameters @params)
		{
			this.x = @params.getX();
			this.elSpec = new ElGamalParameterSpec(@params.getParameters().getP(), @params.getParameters().getG());
		}

		public virtual string getAlgorithm()
		{
			return "ElGamal";
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
			return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(getX()));
		}

		public virtual ElGamalParameterSpec getParameters()
		{
			return elSpec;
		}

		public virtual DHParameterSpec getParams()
		{
			return new DHParameterSpec(elSpec.getP(), elSpec.getG());
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		private void readObject(ObjectInputStream @in)
		{
			x = (BigInteger)@in.readObject();

			this.elSpec = new ElGamalParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject());
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(this.getX());
			@out.writeObject(elSpec.getP());
			@out.writeObject(elSpec.getG());
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