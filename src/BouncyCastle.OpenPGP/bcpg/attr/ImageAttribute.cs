namespace org.bouncycastle.bcpg.attr
{


	/// <summary>
	/// Basic type for a image attribute packet.
	/// </summary>
	public class ImageAttribute : UserAttributeSubpacket
	{
		public const int JPEG = 1;

		private static readonly byte[] ZEROES = new byte[12];

		private int hdrLength;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private int version_Renamed;
		private int encoding;
		private byte[] imageData;

		public ImageAttribute(byte[] data) : this(false, data)
		{
		}

		public ImageAttribute(bool forceLongLength, byte[] data) : base(org.bouncycastle.bcpg.UserAttributeSubpacketTags_Fields.IMAGE_ATTRIBUTE, forceLongLength, data)
		{

			hdrLength = ((data[1] & 0xff) << 8) | (data[0] & 0xff);
			version_Renamed = data[2] & 0xff;
			encoding = data[3] & 0xff;

			imageData = new byte[data.Length - hdrLength];
			JavaSystem.arraycopy(data, hdrLength, imageData, 0, imageData.Length);
		}

		public ImageAttribute(int imageType, byte[] imageData) : this(toByteArray(imageType, imageData))
		{
		}

		private static byte[] toByteArray(int imageType, byte[] imageData)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			try
			{
				bOut.write(0x10);
				bOut.write(0x00);
				bOut.write(0x01);
				bOut.write(imageType);
				bOut.write(ZEROES);
				bOut.write(imageData);
			}
			catch (IOException)
			{
				throw new RuntimeException("unable to encode to byte array!");
			}

			return bOut.toByteArray();
		}

		public virtual int version()
		{
			return version_Renamed;
		}

		public virtual int getEncoding()
		{
			return encoding;
		}

		public virtual byte[] getImageData()
		{
			return imageData;
		}
	}

}