using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using Strings = org.bouncycastle.util.Strings;

	public class JDKDSAPublicKey : DSAPublicKey
	{
		private const long serialVersionUID = 1752452449903495175L;

		private BigInteger y;
		private DSAParams dsaSpec;

		public JDKDSAPublicKey(DSAPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.dsaSpec = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
		}

		public JDKDSAPublicKey(DSAPublicKey key)
		{
			this.y = key.getY();
			this.dsaSpec = key.getParams();
		}

		public JDKDSAPublicKey(DSAPublicKeyParameters @params)
		{
			this.y = @params.getY();
			this.dsaSpec = new DSAParameterSpec(@params.getParameters().getP(), @params.getParameters().getQ(), @params.getParameters().getG());
		}

		public JDKDSAPublicKey(BigInteger y, DSAParameterSpec dsaSpec)
		{
			this.y = y;
			this.dsaSpec = dsaSpec;
		}

		public JDKDSAPublicKey(SubjectPublicKeyInfo info)
		{

			ASN1Integer derY;

			try
			{
				derY = (ASN1Integer)info.parsePublicKey();
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("invalid info structure in DSA public key");
			}

			this.y = derY.getValue();

			if (isNotNull(info.getAlgorithm().getParameters()))
			{
				DSAParameter @params = DSAParameter.getInstance(info.getAlgorithm().getParameters());

				this.dsaSpec = new DSAParameterSpec(@params.getP(), @params.getQ(), @params.getG());
			}
		}

		private bool isNotNull(ASN1Encodable parameters)
		{
			return parameters != null && !DERNull.INSTANCE.Equals(parameters);
		}

		public virtual string getAlgorithm()
		{
			return "DSA";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			try
			{
				if (dsaSpec == null)
				{
					return (new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa), new ASN1Integer(y))).getEncoded(ASN1Encoding_Fields.DER);
				}

				return (new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG())), new ASN1Integer(y))).getEncoded(ASN1Encoding_Fields.DER);
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

		public virtual BigInteger getY()
		{
			return y;
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("DSA Public Key").append(nl);
			buf.append("            y: ").append(this.getY().ToString(16)).append(nl);

			return buf.ToString();
		}

		public override int GetHashCode()
		{
			return this.getY().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getQ().GetHashCode();
		}

		public override bool Equals(object o)
		{
			if (!(o is DSAPublicKey))
			{
				return false;
			}

			DSAPublicKey other = (DSAPublicKey)o;

			return this.getY().Equals(other.getY()) && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getQ().Equals(other.getParams().getQ());
		}

		private void readObject(ObjectInputStream @in)
		{
			this.y = (BigInteger)@in.readObject();
			this.dsaSpec = new DSAParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject(), (BigInteger)@in.readObject());
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(y);
			@out.writeObject(dsaSpec.getP());
			@out.writeObject(dsaSpec.getQ());
			@out.writeObject(dsaSpec.getG());
		}
	}

}