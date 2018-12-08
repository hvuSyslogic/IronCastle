using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using McEliecePrivateKey = org.bouncycastle.pqc.asn1.McEliecePrivateKey;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceKeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
	using McEliecePrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
	using GF2mField = org.bouncycastle.pqc.math.linearalgebra.GF2mField;
	using Permutation = org.bouncycastle.pqc.math.linearalgebra.Permutation;
	using PolynomialGF2mSmallM = org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

	/// <summary>
	/// This class implements a McEliece private key and is usually instantiated by
	/// the <seealso cref="McElieceKeyPairGenerator"/> or <seealso cref="McElieceKeyFactorySpi"/>.
	/// </summary>
	public class BCMcEliecePrivateKey : CipherParameters, PrivateKey
	{
		private const long serialVersionUID = 1L;

		private McEliecePrivateKeyParameters @params;

		public BCMcEliecePrivateKey(McEliecePrivateKeyParameters @params)
		{
			this.@params = @params;
		}

		/// <summary>
		/// Return the name of the algorithm.
		/// </summary>
		/// <returns> "McEliece" </returns>
		public virtual string getAlgorithm()
		{
			return "McEliece";
		}

		/// <returns> the length of the code </returns>
		public virtual int getN()
		{
			return @params.getN();
		}

		/// <returns> the dimension of the code </returns>
		public virtual int getK()
		{
			return @params.getK();
		}

		/// <returns> the finite field </returns>
		public virtual GF2mField getField()
		{
			return @params.getField();
		}

		/// <returns> the irreducible Goppa polynomial </returns>
		public virtual PolynomialGF2mSmallM getGoppaPoly()
		{
			return @params.getGoppaPoly();
		}

		/// <returns> the k x k random binary non-singular matrix S </returns>
		public virtual GF2Matrix getSInv()
		{
			return @params.getSInv();
		}

		/// <returns> the permutation used to generate the systematic check matrix </returns>
		public virtual Permutation getP1()
		{
			return @params.getP1();
		}

		/// <returns> the permutation used to compute the public generator matrix </returns>
		public virtual Permutation getP2()
		{
			return @params.getP2();
		}

		/// <returns> the canonical check matrix </returns>
		public virtual GF2Matrix getH()
		{
			return @params.getH();
		}

		/// <returns> the matrix for computing square roots in <tt>(GF(2^m))^t</tt> </returns>
		public virtual PolynomialGF2mSmallM[] getQInv()
		{
			return @params.getQInv();
		}

		/*
		 * @return a human readable form of the key
		 */
		// TODO:
	//    public String toString()
	//    {
	//        String result = " length of the code          : " + getN() + Strings.lineSeparator();
	//        result += " dimension of the code       : " + getK() + Strings.lineSeparator();
	//        result += " irreducible Goppa polynomial: " + getGoppaPoly() + Strings.lineSeparator();
	//        result += " permutation P1              : " + getP1() + Strings.lineSeparator();
	//        result += " permutation P2              : " + getP2() + Strings.lineSeparator();
	//        result += " (k x k)-matrix S^-1         : " + getSInv();
	//        return result;
	//    }

		/// <summary>
		/// Compare this key with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{
			if (!(other is BCMcEliecePrivateKey))
			{
				return false;
			}
			BCMcEliecePrivateKey otherKey = (BCMcEliecePrivateKey)other;

			return (getN() == otherKey.getN()) && (getK() == otherKey.getK()) && getField().Equals(otherKey.getField()) && getGoppaPoly().Equals(otherKey.getGoppaPoly()) && getSInv().Equals(otherKey.getSInv()) && getP1().Equals(otherKey.getP1()) && getP2().Equals(otherKey.getP2());
		}

		/// <returns> the hash code of this key </returns>
		public override int GetHashCode()
		{
			int code = @params.getK();

			code = code * 37 + @params.getN();
			code = code * 37 + @params.getField().GetHashCode();
			code = code * 37 + @params.getGoppaPoly().GetHashCode();
			code = code * 37 + @params.getP1().GetHashCode();
			code = code * 37 + @params.getP2().GetHashCode();

			return code * 37 + @params.getSInv().GetHashCode();
		}

		/// <summary>
		/// Return the key data to encode in the SubjectPublicKeyInfo structure.
		/// <para>
		/// The ASN.1 definition of the key structure is
		/// </para>
		/// <pre>
		///   McEliecePrivateKey ::= SEQUENCE {
		///     n          INTEGER                   -- length of the code
		///     k          INTEGER                   -- dimension of the code
		///     fieldPoly  OCTET STRING              -- field polynomial defining GF(2&circ;m)
		///     getGoppaPoly()  OCTET STRING              -- irreducible Goppa polynomial
		///     sInv       OCTET STRING              -- matrix S&circ;-1
		///     p1         OCTET STRING              -- permutation P1
		///     p2         OCTET STRING              -- permutation P2
		///     h          OCTET STRING              -- canonical check matrix
		///     qInv       SEQUENCE OF OCTET STRING  -- matrix used to compute square roots
		///   }
		/// </pre>
		/// </summary>
		/// <returns> the key data to encode in the SubjectPublicKeyInfo structure </returns>
		public virtual byte[] getEncoded()
		{
			McEliecePrivateKey privateKey = new McEliecePrivateKey(@params.getN(), @params.getK(), @params.getField(), @params.getGoppaPoly(), @params.getP1(), @params.getP2(), @params.getSInv());
			PrivateKeyInfo pki;
			try
			{
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.mcEliece);
				pki = new PrivateKeyInfo(algorithmIdentifier, privateKey);
			}
			catch (IOException)
			{
				return null;
			}
			try
			{
				byte[] encoded = pki.getEncoded();
				return encoded;
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual string getFormat()
		{
			return "PKCS#8";
		}

		public virtual AsymmetricKeyParameter getKeyParams()
		{
			return @params;
		}
	}

}