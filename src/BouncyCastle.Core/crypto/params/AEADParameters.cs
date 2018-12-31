using org.bouncycastle.util;

namespace org.bouncycastle.crypto.@params
{
	
	public class AEADParameters : CipherParameters
	{
		private byte[] associatedText;
		private byte[] nonce;
		private KeyParameter key;
		private int macSize;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="key"> key to be used by underlying cipher </param>
		/// <param name="macSize"> macSize in bits </param>
		/// <param name="nonce"> nonce to be used </param>
	   public AEADParameters(KeyParameter key, int macSize, byte[] nonce) : this(key, macSize, nonce, null)
	   {
	   }

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="key"> key to be used by underlying cipher </param>
		/// <param name="macSize"> macSize in bits </param>
		/// <param name="nonce"> nonce to be used </param>
		/// <param name="associatedText"> initial associated text, if any </param>
		public AEADParameters(KeyParameter key, int macSize, byte[] nonce, byte[] associatedText)
		{
			this.key = key;
			this.nonce = Arrays.clone(nonce);
			this.macSize = macSize;
			this.associatedText = Arrays.clone(associatedText);
		}

		public virtual KeyParameter getKey()
		{
			return key;
		}

		public virtual int getMacSize()
		{
			return macSize;
		}

		public virtual byte[] getAssociatedText()
		{
			return Arrays.clone(associatedText);
		}

		public virtual byte[] getNonce()
		{
			return Arrays.clone(nonce);
		}
	}

}