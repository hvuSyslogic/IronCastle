using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{


	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using McElieceCCA2PublicKey = org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceCCA2KeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
	using McElieceCCA2PublicKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

	/// <summary>
	/// This class implements a McEliece CCA2 public key and is usually instantiated
	/// by the <seealso cref="McElieceCCA2KeyPairGenerator"/> or <seealso cref="McElieceCCA2KeyFactorySpi"/>.
	/// </summary>
	public class BCMcElieceCCA2PublicKey : CipherParameters, PublicKey
	{
		private const long serialVersionUID = 1L;

		private McElieceCCA2PublicKeyParameters @params;

		public BCMcElieceCCA2PublicKey(McElieceCCA2PublicKeyParameters @params)
		{
			this.@params = @params;
		}

		/// <summary>
		/// Return the name of the algorithm.
		/// </summary>
		/// <returns> "McEliece" </returns>
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

		/// <returns> the error correction capability of the code </returns>
		public virtual int getT()
		{
			return @params.getT();
		}

		/// <returns> the generator matrix </returns>
		public virtual GF2Matrix getG()
		{
			return @params.getG();
		}

		/// <returns> a human readable form of the key </returns>
		public override string ToString()
		{
			string result = "McEliecePublicKey:\n";
			result += " length of the code         : " + @params.getN() + "\n";
			result += " error correction capability: " + @params.getT() + "\n";
			result += " generator matrix           : " + @params.getG().ToString();
			return result;
		}

		/// <summary>
		/// Compare this key with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{
			if (other == null || !(other is BCMcElieceCCA2PublicKey))
			{
				return false;
			}

			BCMcElieceCCA2PublicKey otherKey = (BCMcElieceCCA2PublicKey)other;

			return (@params.getN() == otherKey.getN()) && (@params.getT() == otherKey.getT()) && (@params.getG().Equals(otherKey.getG()));
		}

		/// <returns> the hash code of this key </returns>
		public override int GetHashCode()
		{
			return 37 * (@params.getN() + 37 * @params.getT()) + @params.getG().GetHashCode();
		}

		/// <summary>
		/// Return the keyData to encode in the SubjectPublicKeyInfo structure.
		/// <para>
		/// The ASN.1 definition of the key structure is
		/// <pre>
		///       McEliecePublicKey ::= SEQUENCE {
		///         n           Integer      -- length of the code
		///         t           Integer      -- error correcting capability
		///         matrixG     OctetString  -- generator matrix as octet string
		///       }
		/// </pre>
		/// </para>
		/// </summary>
		/// <returns> the keyData to encode in the SubjectPublicKeyInfo structure </returns>
		public virtual byte[] getEncoded()
		{
			McElieceCCA2PublicKey key = new McElieceCCA2PublicKey(@params.getN(), @params.getT(), @params.getG(), Utils.getDigAlgId(@params.getDigest()));
			AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.mcElieceCca2);

			try
			{
				SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, key);

				return subjectPublicKeyInfo.getEncoded();
			}
			catch (IOException)
			{
				return null;
			}

		}

		public virtual string getFormat()
		{
			return "X.509";
		}

		public virtual AsymmetricKeyParameter getKeyParams()
		{
			return @params;
		}
	}

}