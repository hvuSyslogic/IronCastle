using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.misc
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// RFC 7914 scrypt parameters.
	/// 
	/// <pre>
	/// scrypt-params ::= SEQUENCE {
	///      salt OCTET STRING,
	///      costParameter INTEGER (1..MAX),
	///      blockSize INTEGER (1..MAX),
	///      parallelizationParameter INTEGER (1..MAX),
	///      keyLength INTEGER (1..MAX) OPTIONAL
	/// }
	/// </pre>
	/// </summary>
	public class ScryptParams : ASN1Object
	{
		private readonly byte[] salt;
		private readonly BigInteger costParameter;
		private readonly BigInteger blockSize;
		private readonly BigInteger parallelizationParameter;
		private readonly BigInteger keyLength;

		public ScryptParams(byte[] salt, int costParameter, int blockSize, int parallelizationParameter) : this(salt, BigInteger.valueOf(costParameter), BigInteger.valueOf(blockSize), BigInteger.valueOf(parallelizationParameter), null)
		{
		}

		public ScryptParams(byte[] salt, int costParameter, int blockSize, int parallelizationParameter, int keyLength) : this(salt, BigInteger.valueOf(costParameter), BigInteger.valueOf(blockSize), BigInteger.valueOf(parallelizationParameter), BigInteger.valueOf(keyLength))
		{
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="salt"> salt value </param>
		/// <param name="costParameter"> specifies the CPU/Memory cost parameter N </param>
		/// <param name="blockSize"> block size parameter r </param>
		/// <param name="parallelizationParameter"> parallelization parameter </param>
		/// <param name="keyLength"> length of key to be derived (in octects) </param>
		public ScryptParams(byte[] salt, BigInteger costParameter, BigInteger blockSize, BigInteger parallelizationParameter, BigInteger keyLength)
		{
			this.salt = Arrays.clone(salt);
			this.costParameter = costParameter;
			this.blockSize = blockSize;
			this.parallelizationParameter = parallelizationParameter;
			this.keyLength = keyLength;
		}

		public static ScryptParams getInstance(object o)
		{
			if (o is ScryptParams)
			{
				return (ScryptParams)o;
			}
			else if (o != null)
			{
				return new ScryptParams(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		private ScryptParams(ASN1Sequence seq)
		{
			if (seq.size() != 4 && seq.size() != 5)
			{
				throw new IllegalArgumentException("invalid sequence: size = " + seq.size());
			}

			this.salt = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
			this.costParameter = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
			this.blockSize = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
			this.parallelizationParameter = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue();

			if (seq.size() == 5)
			{
				this.keyLength = ASN1Integer.getInstance(seq.getObjectAt(4)).getValue();
			}
			else
			{
				this.keyLength = null;
			}
		}

		public virtual byte[] getSalt()
		{
			return Arrays.clone(salt);
		}

		public virtual BigInteger getCostParameter()
		{
			return costParameter;
		}

		public virtual BigInteger getBlockSize()
		{
			return blockSize;
		}

		public virtual BigInteger getParallelizationParameter()
		{
			return parallelizationParameter;
		}

		/// <summary>
		/// Return the length in octets for the derived key.
		/// </summary>
		/// <returns> length for key to be derived (in octets) </returns>
		public virtual BigInteger getKeyLength()
		{
			return keyLength;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new DEROctetString(salt));
			v.add(new ASN1Integer(costParameter));
			v.add(new ASN1Integer(blockSize));
			v.add(new ASN1Integer(parallelizationParameter));
			if (keyLength != null)
			{
				v.add(new ASN1Integer(keyLength));
			}

			return new DERSequence(v);
		}
	}

}