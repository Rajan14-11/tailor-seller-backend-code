# Generated by Django 4.2.1 on 2023-09-10 09:20

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('startseller', '0009_sellerproduct_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='sellerproduct',
            name='user',
            field=models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
