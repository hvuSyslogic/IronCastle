namespace org.bouncycastle.mime.test
{
	public class TestDoneFlag
	{
		private bool done = false;

		public virtual void markDone()
		{
			done = true;
		}

		public virtual bool isDone()
		{
			return done;
		}
	}

}