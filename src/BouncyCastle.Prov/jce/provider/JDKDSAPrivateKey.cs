using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DSAPrivateKeyParameters = org.bouncycastle.crypto.@params.DSAPrivateKeyParameters;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;

	public class JDKDSAPrivateKey : DSAPrivateKey, PKCS12BagAttributeCarrier
	{
		private const long serialVersionUID = -4677259546958385734L;

		internal BigInteger x;
		internal DSAParams dsaSpec;

		private PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public JDKDSAPrivateKey()
		{
		}

		public JDKDSAPrivateKey(DSAPrivateKey key)
		{
			this.x = key.getX();
			this.dsaSpec = key.getParams();
		}

		public JDKDSAPrivateKey(DSAPrivateKeySpec spec)
		{
			this.x = spec.getX();
			this.dsaSpec = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
		}

		public JDKDSAPrivateKey(PrivateKeyInfo info)
		{
			DSAParameter @params = DSAParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
			ASN1Integer derX = ASN1Integer.getInstance(info.parsePrivateKey());

			this.x = derX.getValue();
			this.dsaSpec = new DSAParameterSpec(@params.getP(), @params.getQ(), @params.getG());
		}

		public JDKDSAPrivateKey(DSAPrivateKeyParameters @params)
		{
			this.x = @params.getX();
			this.dsaSpec = new DSAParameterSpec(@params.getParameters().getP(), @params.getParameters().getQ(), @params.getParameters().getG());
		}

		public virtual string getAlgorithm()
		{
			return "DSA";
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
				PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG())), new ASN1Integer(getX()));

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual DSAParams getParams()
		{
			return dsaSpec;
		}

		public virtual BigInteger getX()
		{
			return x;
		}

		public override bool Equals(object o)
		{
			if (!(o is DSAPrivateKey))
			{
				return false;
			}

			DSAPrivateKey other = (DSAPrivateKey)o;

			return this.getX().Equals(other.getX()) && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getQ().Equals(other.getParams().getQ());
		}

		public override int GetHashCode()
		{
			return this.getX().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getQ().GetHashCode();
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

		private void readObject(ObjectInputStream @in)
		{
			this.x = (BigInteger)@in.readObject();
			this.dsaSpec = new DSAParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), (BigInteger)@in.readObject());
			this.attrCarrier = new PKCS12BagAttributeCarrierImpl();

			attrCarrier.readObject(@in);
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(x);
			@out.writeObject(dsaSpec.getP());
			@out.writeObject(dsaSpec.getQ());
			@out.writeObject(dsaSpec.getG());

			attrCarrier.writeObject(@out);
		}
	}

}