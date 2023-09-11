# Generated by Django 4.2.1 on 2023-08-23 17:49

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('startseller', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='MyAdminProduct',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(default='This is a good product')),
                ('AdditionalInfo', models.TextField(default='This is a good product')),
                ('price', models.DecimalField(decimal_places=2, max_digits=8)),
                ('category', models.CharField(choices=[('men', 'men'), ('women', 'women'), ('child', 'child')], default='men', max_length=20)),
                ('image', models.ImageField(upload_to='product_images/')),
                ('quantity', models.PositiveIntegerField(default=0)),
            ],
        ),
        migrations.CreateModel(
            name='MyAdminSellerInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('picture', models.ImageField(upload_to='seller_pics/')),
                ('address', models.TextField()),
                ('contact_details', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='MyAdminSellerProduct',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('seller', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='myadmin_seller_products_myadmin', to='startseller.seller')),
            ],
        ),
    ]
