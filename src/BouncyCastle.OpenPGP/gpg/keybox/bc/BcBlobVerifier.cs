namespace org.bouncycastle.gpg.keybox.bc
{
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using Arrays = org.bouncycastle.util.Arrays;

	public class BcBlobVerifier : BlobVerifier
	{
		private readonly SHA1Digest sha1Digest = new SHA1Digest();
		private readonly MD5Digest md5Digest = new MD5Digest();

		public virtual bool isMatched(byte[] blobData, byte[] blobDigest)
		{
			sha1Digest.update(blobData, 0, blobData.Length);
			byte[] calculatedDigest = new byte[sha1Digest.getDigestSize()];
			sha1Digest.doFinal(calculatedDigest, 0);

			if (!Arrays.constantTimeAreEqual(calculatedDigest, blobDigest))
			{
				//
				// Special case for old key boxes that used MD5.
				//

			  /*
			   http://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob;f=kbx/keybox-blob.c;hb=HEAD#l129
			   SHA-1 checksum (useful for KS syncronisation?)
			   Note, that KBX versions before GnuPG 2.1 used an MD5
			   checksum.  However it was only created but never checked.
			   Thus we do not expect problems if we switch to SHA-1.  If
			   the checksum fails and the first 4 bytes are zero, we can
			   try again with MD5.  SHA-1 has the advantage that it is
			   faster on CPUs with dedicated SHA-1 support.
			  */

				if (blobDigest[0] == 0 && blobDigest[1] == 0 && blobDigest[2] == 0 && blobDigest[3] == 0)
				{
					md5Digest.update(blobData, 0, blobData.Length);

					Arrays.fill(calculatedDigest, (byte)0);

					md5Digest.doFinal(calculatedDigest, 4);

					return Arrays.constantTimeAreEqual(calculatedDigest, blobDigest);
				}

				return false;
			}

			return true;
		}
	}

}