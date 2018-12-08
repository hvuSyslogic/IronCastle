using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.rainbow
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using RainbowPublicKey = org.bouncycastle.pqc.asn1.RainbowPublicKey;
	using RainbowParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
	using RainbowPublicKeyParameters = org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
	using RainbowUtil = org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;
	using KeyUtil = org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
	using RainbowPublicKeySpec = org.bouncycastle.pqc.jcajce.spec.RainbowPublicKeySpec;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// This class implements CipherParameters and PublicKey.
	/// <para>
	/// The public key in Rainbow consists of n - v1 polynomial components of the
	/// private key's F and the field structure of the finite field k.
	/// </para>
	/// </para><para>
	/// The quadratic (or mixed) coefficients of the polynomials from the public key
	/// are stored in the 2-dimensional array in lexicographical order, requiring n *
	/// (n + 1) / 2 entries for each polynomial. The singular terms are stored in a
	/// 2-dimensional array requiring n entries per polynomial, the scalar term of
	/// each polynomial is stored in a 1-dimensional array.
	/// </para><para>
	/// More detailed information on the public key is to be found in the paper of
	/// Jintai Ding, Dieter Schmidt: Rainbow, a New Multivariable Polynomial
	/// Signature Scheme. ACNS 2005: 164-175 (http://dx.doi.org/10.1007/11496137_12)
	/// </p>
	/// </summary>
	public class BCRainbowPublicKey : PublicKey
	{
		private const long serialVersionUID = 1L;

		private short[][] coeffquadratic;
		private short[][] coeffsingular;
		private short[] coeffscalar;
		private int docLength; // length of possible document to sign

		private RainbowParameters rainbowParams;

		/// <summary>
		/// Constructor
		/// </summary>
		/// <param name="docLength"> </param>
		/// <param name="coeffQuadratic"> </param>
		/// <param name="coeffSingular"> </param>
		/// <param name="coeffScalar"> </param>
		public BCRainbowPublicKey(int docLength, short[][] coeffQuadratic, short[][] coeffSingular, short[] coeffScalar)
		{
			this.docLength = docLength;
			this.coeffquadratic = coeffQuadratic;
			this.coeffsingular = coeffSingular;
			this.coeffscalar = coeffScalar;
		}

		/// <summary>
		/// Constructor (used by the <seealso cref="RainbowKeyFactorySpi"/>).
		/// </summary>
		/// <param name="keySpec"> a <seealso cref="RainbowPublicKeySpec"/> </param>
		public BCRainbowPublicKey(RainbowPublicKeySpec keySpec) : this(keySpec.getDocLength(), keySpec.getCoeffQuadratic(), keySpec.getCoeffSingular(), keySpec.getCoeffScalar())
		{
		}

		public BCRainbowPublicKey(RainbowPublicKeyParameters @params) : this(@params.getDocLength(), @params.getCoeffQuadratic(), @params.getCoeffSingular(), @params.getCoeffScalar())
		{
		}

		/// <returns> the docLength </returns>
		public virtual int getDocLength()
		{
			return this.docLength;
		}

		/// <returns> the coeffQuadratic </returns>
		public virtual short[][] getCoeffQuadratic()
		{
			return coeffquadratic;
		}

		/// <returns> the coeffSingular </returns>
		public virtual short[][] getCoeffSingular()
		{
			short[][] copy = new short[coeffsingular.Length][];

			for (int i = 0; i != coeffsingular.Length; i++)
			{
				copy[i] = Arrays.clone(coeffsingular[i]);
			}

			return copy;
		}


		/// <returns> the coeffScalar </returns>
		public virtual short[] getCoeffScalar()
		{
			return Arrays.clone(coeffscalar);
		}

		/// <summary>
		/// Compare this Rainbow public key with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{
			if (other == null || !(other is BCRainbowPublicKey))
			{
				return false;
			}
			BCRainbowPublicKey otherKey = (BCRainbowPublicKey)other;

			return docLength == otherKey.getDocLength() && RainbowUtil.Equals(coeffquadratic, otherKey.getCoeffQuadratic()) && RainbowUtil.Equals(coeffsingular, otherKey.getCoeffSingular()) && RainbowUtil.Equals(coeffscalar, otherKey.getCoeffScalar());
		}

		public override int GetHashCode()
		{
			int hash = docLength;

			hash = hash * 37 + Arrays.GetHashCode(coeffquadratic);
			hash = hash * 37 + Arrays.GetHashCode(coeffsingular);
			hash = hash * 37 + Arrays.GetHashCode(coeffscalar);

			return hash;
		}

		/// <returns> name of the algorithm - "Rainbow" </returns>
		public string getAlgorithm()
		{
			return "Rainbow";
		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual byte[] getEncoded()
		{
			RainbowPublicKey key = new RainbowPublicKey(docLength, coeffquadratic, coeffsingular, coeffscalar);
			AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.rainbow, DERNull.INSTANCE);

			return KeyUtil.getEncodedSubjectPublicKeyInfo(algorithmIdentifier, key);
		}
	}

}