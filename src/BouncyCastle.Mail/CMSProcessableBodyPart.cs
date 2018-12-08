namespace org.bouncycastle.mail.smime
{


	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSProcessable = org.bouncycastle.cms.CMSProcessable;

	/// <summary>
	/// a holding class for a BodyPart to be processed.
	/// </summary>
	public class CMSProcessableBodyPart : CMSProcessable
	{
		private BodyPart bodyPart;

		public CMSProcessableBodyPart(BodyPart bodyPart)
		{
			this.bodyPart = bodyPart;
		}

		public virtual void write(OutputStream @out)
		{
			try
			{
				bodyPart.writeTo(@out);
			}
			catch (MessagingException e)
			{
				throw new CMSException("can't write BodyPart to stream.", e);
			}
		}

		public virtual object getContent()
		{
			return bodyPart;
		}
	}

}