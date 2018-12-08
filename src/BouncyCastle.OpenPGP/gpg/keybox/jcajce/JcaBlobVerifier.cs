﻿namespace org.bouncycastle.gpg.keybox.jcajce
{

	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using Arrays = org.bouncycastle.util.Arrays;

	public class JcaBlobVerifier : BlobVerifier
	{
		private readonly MessageDigest sha1Digest;
		private readonly MessageDigest md5Digest;

		public JcaBlobVerifier(JcaJceHelper helper)
		{
			this.sha1Digest = helper.createDigest("SHA-1");

			// MD5 may not always be available - we'll die later if we actually need it.
			MessageDigest md5;
			try
			{
				md5 = helper.createDigest("MD5");
			}
			catch (NoSuchAlgorithmException)
			{
				md5 = null;
			}
			this.md5Digest = md5;
		}

		public virtual bool isMatched(byte[] blobData, byte[] blobDigest)
		{
			sha1Digest.update(blobData, 0, blobData.Length);

			byte[] calculatedDigest = sha1Digest.digest();

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

					try
					{
						md5Digest.digest(calculatedDigest, 4, md5Digest.getDigestLength());
					}
					catch (DigestException e)
					{
						throw new IllegalStateException("internal buffer to small: " + e.Message, e);
					}

					return Arrays.constantTimeAreEqual(calculatedDigest, blobDigest);
				}

				return false;
			}

			return true;
		}
	}

}