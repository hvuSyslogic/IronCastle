namespace org.bouncycastle.openpgp
{
	using UserAttributeSubpacket = org.bouncycastle.bcpg.UserAttributeSubpacket;
	using ImageAttribute = org.bouncycastle.bcpg.attr.ImageAttribute;


	public class PGPUserAttributeSubpacketVectorGenerator
	{
		private List list = new ArrayList();

		public virtual void setImageAttribute(int imageType, byte[] imageData)
		{
			if (imageData == null)
			{
				throw new IllegalArgumentException("attempt to set null image");
			}

			list.add(new ImageAttribute(imageType, imageData));
		}

		public virtual PGPUserAttributeSubpacketVector generate()
		{
			return new PGPUserAttributeSubpacketVector((UserAttributeSubpacket[])list.toArray(new UserAttributeSubpacket[list.size()]));
		}
	}

}