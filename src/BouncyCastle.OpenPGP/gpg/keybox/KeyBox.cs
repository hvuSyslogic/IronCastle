namespace org.bouncycastle.gpg.keybox
{

	using KeyFingerPrintCalculator = org.bouncycastle.openpgp.@operator.KeyFingerPrintCalculator;

	/// <summary>
	/// KeyBox provides an implementation of the PGP keybox.
	/// </summary>
	public class KeyBox
	{
		private readonly FirstBlob firstBlob;
		private readonly List<KeyBlob> keyBlobs;

		public KeyBox(InputStream input, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier) : this(KeyBoxByteBuffer.wrap(input), keyFingerPrintCalculator, blobVerifier)
		{
		}

		public KeyBox(byte[] encoding, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier) : this(KeyBoxByteBuffer.wrap(encoding), keyFingerPrintCalculator, blobVerifier)
		{
		}

		private KeyBox(KeyBoxByteBuffer buffer, KeyFingerPrintCalculator keyFingerPrintCalculator, BlobVerifier blobVerifier)
		{
			Blob blob = Blob.getInstance(buffer, keyFingerPrintCalculator, blobVerifier);
			if (blob == null)
			{
				throw new IOException("No first blob, is the source zero length?");
			}

			if (!(blob is FirstBlob))
			{
				throw new IOException("First blob is not KeyBox 'First Blob'.");
			}


			FirstBlob firstBlob = (FirstBlob)blob;
			ArrayList<KeyBlob> keyBoxEntries = new ArrayList<KeyBlob>();

			for (Blob materialBlob = Blob.getInstance(buffer, keyFingerPrintCalculator, blobVerifier); materialBlob != null; materialBlob = Blob.getInstance(buffer, keyFingerPrintCalculator, blobVerifier))
			{
				if (materialBlob.getType() == BlobType.FIRST_BLOB)
				{
					throw new IOException("Unexpected second 'FirstBlob', there should only be one FirstBlob at the start of the file.");
				}

				keyBoxEntries.add((KeyBlob)materialBlob);
			}

			this.firstBlob = firstBlob;
			this.keyBlobs = Collections.unmodifiableList(keyBoxEntries);
		}

		public virtual FirstBlob getFirstBlob()
		{
			return firstBlob;
		}

		public virtual List<KeyBlob> getKeyBlobs()
		{
			return keyBlobs;
		}

	}

}