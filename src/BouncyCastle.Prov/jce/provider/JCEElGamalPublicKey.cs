using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.jce.provider
{


	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ElGamalPublicKeyParameters = org.bouncycastle.crypto.@params.ElGamalPublicKeyParameters;
	using KeyUtil = org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
	using ElGamalPublicKey = org.bouncycastle.jce.interfaces.ElGamalPublicKey;
	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;
	using ElGamalPublicKeySpec = org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

	public class JCEElGamalPublicKey : ElGamalPublicKey, DHPublicKey
	{
		internal const long serialVersionUID = 8712728417091216948L;

		private BigInteger y;
		private ElGamalParameterSpec elSpec;

		public JCEElGamalPublicKey(ElGamalPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
		}

		public JCEElGamalPublicKey(DHPublicKeySpec spec)
		{
			this.y = spec.getY();
			this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
		}

		public JCEElGamalPublicKey(ElGamalPublicKey key)
		{
			this.y = key.getY();
			this.elSpec = key.getParameters();
		}

		public JCEElGamalPublicKey(DHPublicKey key)
		{
			this.y = key.getY();
			this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
		}

		public JCEElGamalPublicKey(ElGamalPublicKeyParameters @params)
		{
			this.y = @params.getY();
			this.elSpec = new ElGamalParameterSpec(@params.getParameters().getP(), @params.getParameters().getG());
		}

		public JCEElGamalPublicKey(BigInteger y, ElGamalParameterSpec elSpec)
		{
			this.y = y;
			this.elSpec = elSpec;
		}

		public JCEElGamalPublicKey(SubjectPublicKeyInfo info)
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
			return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(y));
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

		private void readObject(ObjectInputStream @in)
		{
			this.y = (BigInteger)@in.readObject();
			this.elSpec = new ElGamalParameterSpec((BigInteger)@in.readObject(), (BigInteger)@in.readObject());
		}

		private void writeObject(ObjectOutputStream @out)
		{
			@out.writeObject(this.getY());
			@out.writeObject(elSpec.getP());
			@out.writeObject(elSpec.getG());
		}
	}

}