namespace org.bouncycastle.pqc.crypto.gmss
{
	using Digest = org.bouncycastle.crypto.Digest;

	public interface GMSSDigestProvider
	{
		Digest get();
	}

}