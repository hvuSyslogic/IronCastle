using org.bouncycastle.util;

namespace org.bouncycastle.crypto.tls
{
		
	public class BasicTlsPSKIdentity : TlsPSKIdentity
	{
		protected internal byte[] identity;
		protected internal byte[] psk;

		public BasicTlsPSKIdentity(byte[] identity, byte[] psk)
		{
			this.identity = Arrays.clone(identity);
			this.psk = Arrays.clone(psk);
		}

		public BasicTlsPSKIdentity(string identity, byte[] psk)
		{
			this.identity = Strings.toUTF8ByteArray(identity);
			this.psk = Arrays.clone(psk);
		}

		public virtual void skipIdentityHint()
		{
		}

		public virtual void notifyIdentityHint(byte[] psk_identity_hint)
		{
		}

		public virtual byte[] getPSKIdentity()
		{
			return identity;
		}

		public virtual byte[] getPSK()
		{
			return psk;
		}

	}

}