namespace org.bouncycastle.gpg.keybox
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	public class UserID
	{
		private readonly long offsetToUserId;
		private readonly long lengthOfUserId;
		private readonly int userIdFlags;
		private readonly int validity;
		private readonly int reserved;
		private readonly byte[] userID;

		private UserID(long offsetToUserId, long lengthOfUserId, int userIdFlags, int validity, int reserved, byte[] userID)
		{
			this.offsetToUserId = offsetToUserId;
			this.lengthOfUserId = lengthOfUserId;
			this.userIdFlags = userIdFlags;
			this.validity = validity;
			this.reserved = reserved;
			this.userID = userID;
		}

		internal static UserID getInstance(object src, int @base)
		{
			if (src is UserID)
			{
				return (UserID)src;
			}

			KeyBoxByteBuffer buffer = KeyBoxByteBuffer.wrap(src);

			long offsetToUserId = buffer.u32();
			long lengthOfUserId = buffer.u32();
			int specialUserIdFlags = buffer.u16();


			int validity = buffer.u8();
			int reserved = buffer.u8();

			byte[] userID = buffer.rangeOf((int)(@base + offsetToUserId), (int)(@base + offsetToUserId + lengthOfUserId));


			return new UserID(offsetToUserId, lengthOfUserId, specialUserIdFlags, validity, reserved, userID);

		}


		public virtual long getOffsetToUserId()
		{
			return offsetToUserId;
		}

		public virtual long getLengthOfUserId()
		{
			return lengthOfUserId;
		}

		public virtual long getUserIdFlags()
		{
			return userIdFlags;
		}

		public virtual int getValidity()
		{
			return validity;
		}

		public virtual int getReserved()
		{
			return reserved;
		}

		public virtual byte[] getUserID()
		{
			return Arrays.clone(userID);
		}

		public virtual string getUserIDAsString()
		{
			return Strings.fromUTF8ByteArray(userID);
		}
	}

}