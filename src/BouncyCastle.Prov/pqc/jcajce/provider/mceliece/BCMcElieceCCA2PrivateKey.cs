using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using McElieceCCA2PrivateKey = org.bouncycastle.pqc.asn1.McElieceCCA2PrivateKey;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceCCA2KeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
	using McElieceCCA2PrivateKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
	using GF2mField = org.bouncycastle.pqc.math.linearalgebra.GF2mField;
	using Permutation = org.bouncycastle.pqc.math.linearalgebra.Permutation;
	using PolynomialGF2mSmallM = org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

	/// <summary>
	/// This class implements a McEliece CCA2 private key and is usually instantiated
	/// by the <seealso cref="McElieceCCA2KeyPairGenerator"/> or <seealso cref="McElieceCCA2KeyFactorySpi"/>.
	/// </summary>
	/// <seealso cref= McElieceCCA2KeyPairGenerator </seealso>
	public class BCMcElieceCCA2PrivateKey : PrivateKey
	{
		private const long serialVersionUID = 1L;

		private McElieceCCA2PrivateKeyParameters @params;

		public BCMcElieceCCA2PrivateKey(McElieceCCA2PrivateKeyParameters @params)
		{
			this.@params = @params;
		}

		/// <summary>
		/// Return the name of the algorithm.
		/// </summary>
		/// <returns> "McEliece-CCA2" </returns>
		public virtual string getAlgorithm()
		{
			return "McEliece-CCA2";
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

		/// <returns> the degree of the Goppa polynomial (error correcting capability) </returns>
		public virtual int getT()
		{
			return @params.getGoppaPoly().getDegree();
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

		/// <returns> the permutation vector </returns>
		public virtual Permutation getP()
		{
			return @params.getP();
		}

		/// <returns> the canonical check matrix </returns>
		public virtual GF2Matrix getH()
		{
			return @params.getH();
		}

		/// <returns> the matrix used to compute square roots in <tt>(GF(2^m))^t</tt> </returns>
		public virtual PolynomialGF2mSmallM[] getQInv()
		{
			return @params.getQInv();
		}

		/// <returns> a human readable form of the key </returns>
		// TODO:
	//    public String toString()
	//    {
	//        String result = "";
	//        result += " extension degree of the field      : " + getN() + "\n";
	//        result += " dimension of the code              : " + getK() + "\n";
	//        result += " irreducible Goppa polynomial       : " + getGoppaPoly() + "\n";
	//        return result;
	//    }

		/// <summary>
		/// Compare this key with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{
			if (other == null || !(other is BCMcElieceCCA2PrivateKey))
			{
				return false;
			}

			BCMcElieceCCA2PrivateKey otherKey = (BCMcElieceCCA2PrivateKey)other;

			return (getN() == otherKey.getN()) && (getK() == otherKey.getK()) && getField().Equals(otherKey.getField()) && getGoppaPoly().Equals(otherKey.getGoppaPoly()) && getP().Equals(otherKey.getP()) && getH().Equals(otherKey.getH());
		}

		/// <returns> the hash code of this key </returns>
		public override int GetHashCode()
		{
			int code = @params.getK();

			code = code * 37 + @params.getN();
			code = code * 37 + @params.getField().GetHashCode();
			code = code * 37 + @params.getGoppaPoly().GetHashCode();
			code = code * 37 + @params.getP().GetHashCode();

			return code * 37 + @params.getH().GetHashCode();
		}

		/// <summary>
		/// Return the keyData to encode in the SubjectPublicKeyInfo structure.
		/// <para>
		/// The ASN.1 definition of the key structure is
		/// <pre>
		///   McEliecePrivateKey ::= SEQUENCE {
		///     m             INTEGER                  -- extension degree of the field
		///     k             INTEGER                  -- dimension of the code
		///     field         OCTET STRING             -- field polynomial
		///     goppaPoly     OCTET STRING             -- irreducible Goppa polynomial
		///     p             OCTET STRING             -- permutation vector
		///     matrixH       OCTET STRING             -- canonical check matrix
		///     sqRootMatrix  SEQUENCE OF OCTET STRING -- square root matrix
		///   }
		/// </pre>
		/// </para>
		/// </summary>
		/// <returns> the keyData to encode in the SubjectPublicKeyInfo structure </returns>
		public virtual byte[] getEncoded()
		{
			PrivateKeyInfo pki;
			try
			{
				McElieceCCA2PrivateKey privateKey = new McElieceCCA2PrivateKey(getN(), getK(), getField(), getGoppaPoly(), getP(), Utils.getDigAlgId(@params.getDigest()));
				AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.mcElieceCca2);

				pki = new PrivateKeyInfo(algorithmIdentifier, privateKey);

				return pki.getEncoded();
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