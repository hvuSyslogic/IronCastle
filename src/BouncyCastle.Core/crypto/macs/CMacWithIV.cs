namespace org.bouncycastle.crypto.macs
{

	/// <summary>
	/// A non-NIST variant which allows passing of an IV to the underlying CBC cipher.
	/// <para>Note: there isn't really a good reason to use an IV here, use the regular CMac where possible.</para>
	/// </summary>
	public class CMacWithIV : CMac
	{
		public CMacWithIV(BlockCipher cipher) : base(cipher)
		{
		}

		public CMacWithIV(BlockCipher cipher, int macSizeInBits) : base(cipher, macSizeInBits)
		{
		}

		public override void validate(CipherParameters @params)
		{
			// accept all
		}
	}

}