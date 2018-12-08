namespace org.bouncycastle.crypto.engines
{
	/// <summary>
	/// an implementation of the AES Key Wrapper from the NIST Key Wrap
	/// Specification.
	/// <para>
	/// For further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
	/// </para>
	/// </summary>
	public class AESWrapEngine : RFC3394WrapEngine
	{
		/// <summary>
		/// Create a regular AESWrapEngine specifying the encrypt for wrapping, decrypt for unwrapping.
		/// </summary>
		public AESWrapEngine() : base(new AESEngine())
		{
		}

		/// <summary>
		/// Create an AESWrapEngine where the underlying cipher is set to decrypt for wrapping, encrypt for unwrapping.
		/// </summary>
		/// <param name="useReverseDirection"> true if underlying cipher should be used in decryption mode, false otherwise. </param>
		public AESWrapEngine(bool useReverseDirection) : base(new AESEngine(), useReverseDirection)
		{
		}
	}

}