namespace org.bouncycastle.openpgp.@operator.bc
{

	using BCPGKey = org.bouncycastle.bcpg.BCPGKey;
	using MPInteger = org.bouncycastle.bcpg.MPInteger;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using RSAPublicBCPGKey = org.bouncycastle.bcpg.RSAPublicBCPGKey;
	using Digest = org.bouncycastle.crypto.Digest;
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;

	public class BcKeyFingerprintCalculator : KeyFingerPrintCalculator
	{
		public virtual byte[] calculateFingerprint(PublicKeyPacket publicPk)
		{
			BCPGKey key = publicPk.getKey();
			Digest digest;

			if (publicPk.getVersion() <= 3)
			{
				RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

				try
				{
					digest = new MD5Digest();

					byte[] bytes = (new MPInteger(rK.getModulus())).getEncoded();
					digest.update(bytes, 2, bytes.Length - 2);

					bytes = (new MPInteger(rK.getPublicExponent())).getEncoded();
					digest.update(bytes, 2, bytes.Length - 2);
				}
				catch (IOException e)
				{
					throw new PGPException("can't encode key components: " + e.Message, e);
				}
			}
			else
			{
				try
				{
					byte[] kBytes = publicPk.getEncodedContents();

					digest = new SHA1Digest();

					digest.update(unchecked((byte)0x99));
					digest.update((byte)(kBytes.Length >> 8));
					digest.update((byte)kBytes.Length);
					digest.update(kBytes, 0, kBytes.Length);
				}
				catch (IOException e)
				{
					throw new PGPException("can't encode key components: " + e.Message, e);
				}
			}

			byte[] digBuf = new byte[digest.getDigestSize()];

			digest.doFinal(digBuf, 0);

			return digBuf;
		}
	}

}