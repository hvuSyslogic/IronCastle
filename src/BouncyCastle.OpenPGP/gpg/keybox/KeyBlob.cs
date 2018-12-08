namespace org.bouncycastle.gpg.keybox
{

	/// <summary>
	/// A PGP blob holds key material.
	/// </summary>
	public class KeyBlob : Blob
	{
		private readonly int blobFlags;
		private readonly int keyNumber;
		private readonly List<KeyInformation> keyInformation;
		private readonly byte[] serialNumber;
		private readonly int numberOfUserIDs;
		private readonly List<UserID> userIds;
		private readonly int numberOfSignatures;
		private readonly List<long> expirationTime;
		private readonly int assignedOwnerTrust;
		private readonly int allValidity;
		private readonly long recheckAfter;
		private readonly long newestTimestamp;
		private readonly long blobCreatedAt;
		private readonly byte[] keyBytes;
		private readonly byte[] reserveBytes;
		private readonly byte[] checksum;

		public KeyBlob(int @base, long length, BlobType type, int version, int blobFlags, int keyNumber, List<KeyInformation> keyInformation, byte[] serialNumber, int numberOfUserIDs, List<UserID> userIds, int numberOfSignatures, List<long> expirationTime, int assignedOwnerTrust, int allValidity, long recheckAfter, long newestTimestamp, long blobCreatedAt, byte[] keyBytes, byte[] reserveBytes, byte[] checksum) : base(@base, length, type, version)
		{
			this.blobFlags = blobFlags;
			this.keyNumber = keyNumber;
			this.keyInformation = keyInformation;
			this.serialNumber = serialNumber;
			this.numberOfUserIDs = numberOfUserIDs;
			this.userIds = userIds;
			this.numberOfSignatures = numberOfSignatures;
			this.expirationTime = expirationTime;
			this.assignedOwnerTrust = assignedOwnerTrust;
			this.allValidity = allValidity;
			this.recheckAfter = recheckAfter;
			this.newestTimestamp = newestTimestamp;
			this.blobCreatedAt = blobCreatedAt;
			this.keyBytes = keyBytes;
			this.reserveBytes = reserveBytes;
			this.checksum = checksum;
		}

		internal static void verifyDigest(int @base, long length, KeyBoxByteBuffer buffer, BlobVerifier blobVerifier)
		{
			byte[] blobData = buffer.rangeOf(@base, (int)(@base + length - 20));
			byte[] blobDigest = buffer.rangeOf((int)(@base + length - 20), (int)(@base + length));

			if (!blobVerifier.isMatched(blobData, blobDigest))
			{
				throw new IOException("Blob with base offset of " + @base + " has incorrect digest.");
			}
		}

		public virtual int getBlobFlags()
		{
			return blobFlags;
		}

		public virtual int getKeyNumber()
		{
			return keyNumber;
		}

		public virtual List<KeyInformation> getKeyInformation()
		{
			return keyInformation;
		}

		public virtual byte[] getSerialNumber()
		{
			return serialNumber;
		}

		public virtual int getNumberOfUserIDs()
		{
			return numberOfUserIDs;
		}

		public virtual List<UserID> getUserIds()
		{
			return userIds;
		}

		public virtual int getNumberOfSignatures()
		{
			return numberOfSignatures;
		}


		public virtual List<long> getExpirationTime()
		{
			return expirationTime;
		}

		public virtual int getAssignedOwnerTrust()
		{
			return assignedOwnerTrust;
		}

		public virtual int getAllValidity()
		{
			return allValidity;
		}

		public virtual long getRecheckAfter()
		{
			return recheckAfter;
		}

		public virtual long getNewestTimestamp()
		{
			return newestTimestamp;
		}

		public virtual long getBlobCreatedAt()
		{
			return blobCreatedAt;
		}

		public virtual byte[] getKeyBytes()
		{
			return keyBytes;
		}

		public virtual byte[] getReserveBytes()
		{
			return reserveBytes;
		}

		public virtual byte[] getChecksum()
		{
			return checksum;
		}
	}

}