using org.bouncycastle.crypto;

namespace org.bouncycastle.pqc.crypto.gmss
{
	
	public interface GMSSDigestProvider
	{
		Digest get();
	}

}