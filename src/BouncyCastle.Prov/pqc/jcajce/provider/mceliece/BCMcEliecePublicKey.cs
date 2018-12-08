using org.bouncycastle.pqc.asn1;

namespace org.bouncycastle.pqc.jcajce.provider.mceliece
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using McEliecePublicKey = org.bouncycastle.pqc.asn1.McEliecePublicKey;
	using PQCObjectIdentifiers = org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
	using McElieceKeyPairGenerator = org.bouncycastle.pqc.crypto.mceliece.McElieceKeyPairGenerator;
	using McEliecePublicKeyParameters = org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
	using GF2Matrix = org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

	/// <summary>
	/// This class implements a McEliece public key and is usually instantiated by
	/// the <seealso cref="McElieceKeyPairGenerator"/> or <seealso cref="McElieceKeyFactorySpi"/>.
	/// </summary>
	public class BCMcEliecePublicKey : PublicKey
	{
		private const long serialVersionUID = 1L;

		private McEliecePublicKeyParameters @params;

		public BCMcEliecePublicKey(McEliecePublicKeyParameters @params)
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
			result += " generator matrix           : " + @params.getG();
			return result;
		}

		/// <summary>
		/// Compare this key with another object.
		/// </summary>
		/// <param name="other"> the other object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{
			if (other is BCMcEliecePublicKey)
			{
				BCMcEliecePublicKey otherKey = (BCMcEliecePublicKey)other;

				return (@params.getN() == otherKey.getN()) && (@params.getT() == otherKey.getT()) && (@params.getG().Equals(otherKey.getG()));
			}

			return false;
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
		/// </para>
		/// <pre>
		///       McEliecePublicKey ::= SEQUENCE {
		///         n           Integer      -- length of the code
		///         t           Integer      -- error correcting capability
		///         matrixG     OctetString  -- generator matrix as octet string
		///       }
		/// </pre> </summary>
		/// <returns> the keyData to encode in the SubjectPublicKeyInfo structure </returns>
		public virtual byte[] getEncoded()
		{
			McEliecePublicKey key = new McEliecePublicKey(@params.getN(), @params.getT(), @params.getG());
			AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers_Fields.mcEliece);

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