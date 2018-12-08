using System;

namespace javax.crypto.spec
{

	/// <summary>
	/// This class specifies a secret key in a provider-independent fashion.
	/// <para>
	/// It can be used to construct a <code>SecretKey</code> from a byte array,
	/// without having to go through a (provider-based)
	/// <code>SecretKeyFactory</code>.
	/// </para>
	/// <para>
	/// This class is only useful for raw secret keys that can be represented as
	/// a byte array and have no key parameters associated with them, e.g., DES or
	/// Triple DES keys.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SecretKey </seealso>
	/// <seealso cref= javax.crypto.SecretKeyFactory </seealso>
	public class SecretKeySpec : KeySpec, SecretKey
	{
		private const long serialVersionUID = 6577238317307289933L;

		private string algorithm;
		private byte[] key;

		/// <summary>
		/// Constructs a secret key from the given byte array.
		/// <para>
		/// This constructor does not check if the given bytes indeed specify a
		/// secret key of the specified algorithm. For example, if the algorithm is
		/// DES, this constructor does not check if <code>key</code> is 8 bytes
		/// long, and also does not check for weak or semi-weak keys.
		/// In order for those checks to be performed, an algorithm-specific
		/// <i>key specification</i> class (in this case:
		/// <a href = "DESKeySpec.html"><code>DESKeySpec</code></a>)
		/// should be used.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the key material of the secret key. </param>
		/// <param name="algorithm">  the name of the secret-key algorithm to be associated
		/// See Appendix A in the Java Cryptography Extension API Specification &amp; Reference 
		/// for information about standard algorithm names. </param>
		public SecretKeySpec(byte[] key, string algorithm)
		{
			if (key == null)
			{
				throw new IllegalArgumentException("null key passed");
			}

			if (string.ReferenceEquals(algorithm, null))
			{
				throw new IllegalArgumentException("null algorithm passed");
			}

			this.key = new byte[key.Length];
			JavaSystem.arraycopy(key, 0, this.key, 0, key.Length);
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Constructs a secret key from the given byte array, using the first
		/// <code>len</code> bytes of <code>key</code>, starting at
		/// <code>offset</code> inclusive.
		/// <para>
		/// The bytes that constitute the secret key are those between <code>key[offset]</code> and
		/// <code>key[offset+len-1]</code> inclusive.
		/// </para>
		/// <para>
		/// This constructor does not check if the given bytes indeed specify a
		/// secret key of the specified algorithm. For example, if the algorithm is
		/// DES, this constructor does not check if <code>key</code> is 8 bytes
		/// long, and also does not check for weak or semi-weak keys.
		/// In order for those checks to be performed, an algorithm-specific key
		/// specification class (in this case: <a href = "DESKeySpec.html"><code>DESKeySpec</code></a>)
		/// must be used.
		/// 
		/// </para>
		/// </summary>
		/// <param name="key"> the key material of the secret key. </param>
		/// <param name="offset"> the offset in <code>key</code> where the key material starts. </param>
		/// <param name="len"> the length of the key material. </param>
		/// <param name="algorithm"> the name of the secret-key algorithm to be associated
		/// with the given key material. See Appendix A in the Java Cryptography Extension API
		/// Specification &amp; Reference for information about standard algorithm names. </param>
		public SecretKeySpec(byte[] key, int offset, int len, string algorithm)
		{
			if (key == null)
			{
				throw new IllegalArgumentException("Null key passed");
			}

			if ((key.Length - offset) < len)
			{
				throw new IllegalArgumentException("Bad offset/len");
			}

			if (string.ReferenceEquals(algorithm, null))
			{
				throw new IllegalArgumentException("Null algorithm string passed");
			}

			this.key = new byte[len];
			JavaSystem.arraycopy(key, offset, this.key, 0, len);
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Returns the name of the algorithm associated with this secret key.
		/// </summary>
		/// <returns> the secret key algorithm. </returns>
		public virtual string getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// Returns the name of the encoding format for this secret key.
		/// </summary>
		/// <returns> the string "RAW". </returns>
		public virtual string getFormat()
		{
			return "RAW";
		}

		/// <summary>
		/// Returns the key material of this secret key.
		/// </summary>
		/// <returns> the key material </returns>
		public virtual byte[] getEncoded()
		{
			byte[] tmp = new byte[key.Length];

			JavaSystem.arraycopy(key, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// Calculates a hash code value for the object.
		/// Objects that are equal will also have the same hashcode.
		/// </summary>
		public override int GetHashCode()
		{
			int code = algorithm.ToUpper().GetHashCode();

			for (int i = 0; i != this.key.Length; i++)
			{
				code ^= this.key[i] << (8 * (i % 4));
			}

			return code;
		}

		public override bool Equals(object obj)
		{
			if ((obj == null) || !(obj is SecretKeySpec))
			{
				return false;
			}

			SecretKeySpec spec = (SecretKeySpec)obj;

			if (!this.algorithm.Equals(spec.algorithm, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			if (this.key.Length != spec.key.Length)
			{
				return false;
			}

			for (int i = 0; i != this.key.Length; i++)
			{
				if (this.key[i] != spec.key[i])
				{
					return false;
				}
			}

			return true;
		}
	}

}