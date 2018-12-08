namespace org.bouncycastle.cms
{
	using Selector = org.bouncycastle.util.Selector;

	public abstract class RecipientId : Selector
	{
		public abstract bool match(T obj);
		public const int keyTrans = 0;
		public const int kek = 1;
		public const int keyAgree = 2;
		public const int password = 3;

		private readonly int type;

		public RecipientId(int type)
		{
			this.type = type;
		}

		/// <summary>
		/// Return the type code for this recipient ID.
		/// </summary>
		/// <returns> one of keyTrans, kek, keyAgree, password </returns>
		public virtual int getType()
		{
			return type;
		}

		public abstract object clone();
	}

}