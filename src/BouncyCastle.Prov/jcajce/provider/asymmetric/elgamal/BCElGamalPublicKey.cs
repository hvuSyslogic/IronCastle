using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{


	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;
	using ElGamalPublicKey = org.bouncycastle.jce.interfaces.ElGamalPublicKey;
	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;
	using ElGamalPublicKeySpec = org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

	public class BCElGamalPublicKey : ElGamalPublicKey, DHPublicKey
	{
		internal const long serialVersionUID = 8712728417091216948L;

		private BigInteger y;
		[NonSerialized]
		private ElGamalParameterSpec elSpec;

		public BCElGamalPublicKey(ElGamalPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
		}

		public BCElGamalPublicKey(DHPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
		}

		public BCElGamalPublicKey(ElGamalPublicKey key)
		{
			this.y = key.getY();
			this.elSpec = key.getParameters();
		}

		public BCElGamalPublicKey(DHPublicKey key)
		{
			this.y = key.getY();
			this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
		}

		public BCElGamalPublicKey(ElGamalPublicKeyParameters @params)
		{
			this.y = @params.getY();
			this.elSpec = new ElGamalParameterSpec(@params.getParameters().getP(), @params.getParameters().getG());
		}

		public BCElGamalPublicKey(BigInteger y, ElGamalParameterSpec elSpec)
		{
			this.y = y;
			this.elSpec = elSpec;
		}

		public BCElGamalPublicKey(SubjectPublicKeyInfo info)
		{
			ElGamalParameter @params = ElGamalParameter.getInstance(info.getAlgorithm().getParameters());
			ASN1Integer derY = null;

			try
			{
				derY = (ASN1Integer)info.parsePublicKey();
			}
			catch (IOException)
			{
				throw new IllegalArgumentException("invalid info structure in DSA public key");
			}

			this.y = derY.getValue();
			this.elSpec = new ElGamalParameterSpec(@params.getP(), @params.getG());
		}

		public virtual string getAlgorithm()
		{
			return "ElGamal";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			try
			{
				SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(y));

				return info.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual ElGamalParameterSpec getParameters()
		{
			return elSpec;
		}

		public virtual DHParameterSpec getParams()
		{
			return new DHParameterSpec(elSpec.getP(), elSpec.getG());
		}

		public virtual BigInteger getY()
		{
			return y;
		}

		public override int GetHashCode()
		{
			return this.getY().GetHashCode() ^ this.getParams().getG().GetHashCode() ^ this.getParams().getP().GetHashCode() ^ this.getParams().getL();
		}

		public override bool Equals(object o)
		{
			if (!(o is DHPublicKey))
			{
				return false;
			}

			DHPublicKey other = (DHPublicKey)o;

			return this.getY().Equals(other.getY()) && this.getParams().getG().Equals(other.getParams().getG()) && this.getParams().getP().Equals(other.getParams().getP()) && this.getParams().getL() == other.getParams().getL();
		}

		private void readObject(ObjectInputStream @in)
		{
			@in.defaultReadObject();

			this.elSpec = new ElGamalParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject());
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.defaultWriteObject();

			@out.writeObject(elSpec.getP());
			@out.writeObject(elSpec.getG());
		}
	}

}