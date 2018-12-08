namespace org.bouncycastle.gpg.keybox
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;


	/// <summary>
	/// First blob contains meta data about the KeyBox.
	/// </summary>
	public class FirstBlob : Blob
	{
		private readonly int headerFlags;
		private readonly long fileCreatedAt;
		private readonly long lastMaintenanceRun;

		private FirstBlob(int @base, long length, BlobType type, int version, int headerFlags, long fileCreatedAt, long lastMaintenanceRun) : base(@base, length, type, version)
		{
			this.headerFlags = headerFlags;
			this.fileCreatedAt = fileCreatedAt;
			this.lastMaintenanceRun = lastMaintenanceRun;
		}

		internal static FirstBlob parseContent(int @base, long length, BlobType type, int version, KeyBoxByteBuffer buffer)
		{

			int headerFlags = buffer.u16();
			byte[] magic = new byte[4];
			buffer.bN(magic);

			if (!Arrays.areEqual(magic, magicBytes))
			{
				throw new IOException("Incorrect magic expecting " + Hex.toHexString(magicBytes) + " but got " + Hex.toHexString(magic));
			}


			buffer.u32(); // RFU = Reserved for Future Use
			long fileCreatedAt = buffer.u32();
			long lastMaintenanceRun = buffer.u32();
			buffer.u32(); // RFU
			buffer.u32(); // RFU


			return new FirstBlob(@base, length, type, version, headerFlags, fileCreatedAt, lastMaintenanceRun);
		}

		public virtual int getHeaderFlags()
		{
			return headerFlags;
		}

		public virtual long getFileCreatedAt()
		{
			return fileCreatedAt;
		}

		public virtual long getLastMaintenanceRun()
		{
			return lastMaintenanceRun;
		}
	}

}