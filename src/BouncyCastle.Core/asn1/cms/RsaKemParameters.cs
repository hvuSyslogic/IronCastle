using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// RFC 5990 RSA KEM parameters class.
	/// <pre>
	///  RsaKemParameters ::= SEQUENCE {
	///     keyDerivationFunction  KeyDerivationFunction,
	///     keyLength              KeyLength
	///   }
	/// 
	///   KeyDerivationFunction ::= AlgorithmIdentifier
	///   KeyLength ::= INTEGER (1..MAX)
	/// </pre>
	/// </summary>
	public class RsaKemParameters : ASN1Object
	{
		private readonly AlgorithmIdentifier keyDerivationFunction;
		private readonly BigInteger keyLength;

		private RsaKemParameters(ASN1Sequence sequence)
		{
			if (sequence.size() != 2)
			{
				throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
			}
			this.keyDerivationFunction = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
			this.keyLength = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
		}

		public static RsaKemParameters getInstance(object o)
		{
			if (o is RsaKemParameters)
			{
				return (RsaKemParameters)o;
			}
			else if (o != null)
			{
				return new RsaKemParameters(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="keyDerivationFunction"> algorithm ID describing the key derivation function. </param>
		/// <param name="keyLength"> length of key to be derived (in bytes). </param>
		public RsaKemParameters(AlgorithmIdentifier keyDerivationFunction, int keyLength)
		{
			this.keyDerivationFunction = keyDerivationFunction;
			this.keyLength = BigInteger.valueOf(keyLength);
		}

		public virtual AlgorithmIdentifier getKeyDerivationFunction()
		{
			return keyDerivationFunction;
		}

		public virtual BigInteger getKeyLength()
		{
			return keyLength;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyDerivationFunction);
			v.add(new ASN1Integer(keyLength));

			return new DERSequence(v);
		}
	}

}