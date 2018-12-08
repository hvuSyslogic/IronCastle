using org.bouncycastle.asn1.x9;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using Strings = org.bouncycastle.util.Strings;

	public class BCDSAPublicKey : DSAPublicKey
	{
		private const long serialVersionUID = 1752452449903495175L;
		private static BigInteger ZERO = BigInteger.valueOf(0);

		private BigInteger y;

		[NonSerialized]
		private DSAPublicKeyParameters lwKeyParams;
		[NonSerialized]
		private DSAParams dsaSpec;

		public BCDSAPublicKey(DSAPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.dsaSpec = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
			this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
		}

		public BCDSAPublicKey(DSAPublicKey key)
		{
			this.y = key.getY();
			this.dsaSpec = key.getParams();
			this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
		}

		public BCDSAPublicKey(DSAPublicKeyParameters @params)
		{
			this.y = @params.getY();
			if (@params != null)
			{
				this.dsaSpec = new DSAParameterSpec(@params.getParameters().getP(), @params.getParameters().getQ(), @params.getParameters().getG());
			}
			else
			{
				this.dsaSpec = null;
			}
			this.lwKeyParams = @params;
		}

		public BCDSAPublicKey(SubjectPublicKeyInfo info)
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
			else
			{
				this.dsaSpec = null;
			}

			this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
		}

		private bool isNotNull(ASN1Encodable parameters)
		{
			return parameters != null && !DERNull.INSTANCE.Equals(parameters.toASN1Primitive());
		}

		public virtual string getAlgorithm()
		{
			return "DSA";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual DSAPublicKeyParameters engineGetKeyParameters()
		{
			return lwKeyParams;
		}

		public virtual byte[] getEncoded()
		{
			if (dsaSpec == null)
			{
				return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa), new ASN1Integer(y));
			}

			return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers_Fields.id_dsa, (new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG())).toASN1Primitive()), new ASN1Integer(y));
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

			buf.append("DSA Public Key [").append(DSAUtil.generateKeyFingerprint(y, getParams())).append("]").append(nl);
			buf.append("            Y: ").append(this.getY().ToString(16)).append(nl);

			return buf.ToString();
		}

		public override int GetHashCode()
		{
			if (dsaSpec != null)
			{
				return this.getY().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getQ().GetHashCode();
			}
			else
			{
				return this.getY().GetHashCode();
			}
		}

		public override bool Equals(object o)
		{
			if (!(o is DSAPublicKey))
			{
				return false;
			}

			DSAPublicKey other = (DSAPublicKey)o;

			if (this.dsaSpec != null)
			{
				return this.getY().Equals(other.getY()) && other.getParams() != null && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getQ().Equals(other.getParams().getQ());
			}
			else
			{
				return this.getY().Equals(other.getY()) && other.getParams() == null;
			}
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			BigInteger p = (BigInteger)@in.readObject();
			if (p.Equals(ZERO))
			{
				this.dsaSpec = null;
			}
			else
			{
				this.dsaSpec = new DSAParameterSpec(p, (BigInteger)@in.readObject(), (BigInteger)@in.readObject());
			}
			this.lwKeyParams = new DSAPublicKeyParameters(y, DSAUtil.toDSAParameters(dsaSpec));
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			if (dsaSpec == null)
			{
				@out.writeObject(ZERO);
			}
			else
			{
				@out.writeObject(dsaSpec.getP());
				@out.writeObject(dsaSpec.getQ());
				@out.writeObject(dsaSpec.getG());
			}
		}
	}

}