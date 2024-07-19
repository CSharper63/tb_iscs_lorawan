import tarfile
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import time

def is_authorized(id):
    return id in [89187321]

def human_readable_timestamp():
     return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

async def export_json_files(update: Update, context: ContextTypes.DEFAULT_TYPE)->None:
        # chat details
        uid = update.effective_user.id
        chat_id = update.message.chat_id

        # verify authorization by id
        if is_authorized(uid) != True:
             print(f'unauthorized use of /export by {uid} at {human_readable_timestamp()}')
        else:
            root = r'/app'
            wss_path = os.path.join(root, 'wss_messages.json')
            http_path = os.path.join(root, 'requests.json')
            archive_path = os.path.join(root, 'export.tar.gz')

            with tarfile.open(archive_path, "w:gz") as tar:
                tar.add(wss_path, arcname=os.path.basename(wss_path))
                print(f'wss export added to archive')
                tar.add(http_path, arcname=os.path.basename(http_path))
                print(f'http export added to archive')

            with open(archive_path, 'rb') as document:
                await context.bot.send_document(chat_id, document)
                print(f'export sent to {uid} at {human_readable_timestamp()}, chatid: {chat_id}')

            os.remove(archive_path)
            print(f'archived wiped')

app = ApplicationBuilder().token("YOUR_API_KEY").build()

app.add_handler(CommandHandler("export", export_json_files))

app.run_polling()
