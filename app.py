from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, DateTime, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from werkzeug.security import generate_password_hash, check_password_hash
import random

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'  # Mude para uma chave segura em produção

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    session = Session()
    user = session.query(User).get(int(user_id))
    session.close()
    return user
Base = declarative_base()
engine = create_engine('sqlite:///database.db')
Session = sessionmaker(bind=engine)

class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(128))
    numbers = relationship('RandomNumber', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class RandomNumber(Base):
    __tablename__ = 'numbers'
    id = Column(Integer, primary_key=True)
    value = Column(Integer)
    created_at = Column(DateTime, default=datetime.now)
    user_id = Column(Integer, ForeignKey('users.id'))

Base.metadata.drop_all(engine)  # Remove existing tables
Base.metadata.create_all(engine)  # Create new schema

@app.route('/')
def index():
    session = Session()
    numbers = session.query(RandomNumber).order_by(RandomNumber.created_at.desc()).all()
    
    # Calcular pares e ímpares
    even_count = session.query(RandomNumber).filter(RandomNumber.value % 2 == 0).count()
    odd_count = session.query(RandomNumber).filter(RandomNumber.value % 2 != 0).count()
    
    session.close()
    return render_template('index.html', 
                         numbers=numbers,
                         even_count=even_count,
                         odd_count=odd_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session = Session()
        user = session.query(User).filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            session.close()
            return redirect(url_for('index'))
        
        flash('Credenciais inválidas')
        session.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session = Session()
        
        if session.query(User).filter_by(username=username).first():
            flash('Nome de usuário já existe')
            session.close()
            return redirect(url_for('register'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        session.add(new_user)
        session.commit()
        session.close()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/clear', methods=['POST'])
@login_required
def clear_database():
    session = Session()
    try:
        # Delete todos os números do usuário atual
        session.query(RandomNumber).filter_by(user_id=current_user.id).delete()
        session.commit()
        flash('Histórico limpo com sucesso!', 'success')
    except Exception as e:
        session.rollback()
        flash('Erro ao limpar o histórico', 'danger')
    finally:
        session.close()
    return redirect(url_for('index'))

@app.route('/generate', methods=['POST'])
@login_required
def generate():
    session = Session()
    new_number = RandomNumber(
        value=random.randint(1, 100),
        owner=current_user
    )
    session.add(new_number)
    session.commit()
    session.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
